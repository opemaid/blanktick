package com.blanktick.desktop

import com.blanktick.desktop.collect.FullPcScan
import com.blanktick.desktop.collect.FullPcScan.Drive
import com.blanktick.desktop.collect.FullPcScan.DriveOutcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Where the whole-PC scan is, for the screen to draw. */
sealed interface FullScanUiState {
    data object Idle : FullScanUiState

    data object Preparing : FullScanUiState

    /** Nothing can be scanned here, and why. Never shown as a clean result. */
    data class Unavailable(val reason: String) : FullScanUiState

    data class Running(
        val drives: List<Drive>,
        val current: Int,
        val startedAtMillis: Long,
        val finished: List<Pair<Drive, DriveOutcome>>
    ) : FullScanUiState

    data class Done(
        val results: List<Pair<Drive, DriveOutcome>>,
        val elapsedMillis: Long,
        val cancelled: Boolean
    ) : FullScanUiState {
        val threats get() = results.count { it.second is DriveOutcome.Threats }
        val notScanned get() = results.count { it.second is DriveOutcome.NotScanned }

        /** Only true when every drive was read to the end and came back clean. */
        val allClean get() = !cancelled && results.isNotEmpty() && results.all { it.second == DriveOutcome.Clean }
    }
}

/**
 * Runs [FullPcScan] one drive at a time, off the UI thread.
 *
 * Kept out of [AppState] on purpose: it shares nothing with the quick scan's
 * score. A whole-disk pass takes far too long to gate the dashboard on, and
 * its answer is a list of files, not points.
 */
class FullScanController(private val scope: CoroutineScope) {

    private val _state = MutableStateFlow<FullScanUiState>(FullScanUiState.Idle)
    val state: StateFlow<FullScanUiState> = _state

    private var job: Job? = null
    @Volatile private var handle: FullPcScan.Handle? = null
    @Volatile private var cancelled = false

    val isRunning: Boolean
        get() = _state.value is FullScanUiState.Running || _state.value is FullScanUiState.Preparing

    fun start() {
        if (isRunning) return
        cancelled = false
        _state.value = FullScanUiState.Preparing
        job = scope.launch(Dispatchers.IO) {
            val plan = FullPcScan.plan()
            val drives = plan.drives
            if (!plan.canScan || drives == null) {
                _state.value = FullScanUiState.Unavailable(
                    when {
                        plan.scannerPath == null ->
                            "Microsoft Defender's scanner is not on this computer, so there is " +
                                "nothing to read your files with. Nothing was scanned."
                        plan.defenderEnabled != true ->
                            "Microsoft Defender is switched off or replaced by another antivirus, " +
                                "so it will not scan on request. Nothing was scanned — run a full " +
                                "scan from your antivirus instead."
                        else -> "No local drives could be listed, so nothing was scanned."
                    }
                )
                return@launch
            }
            val scanner = plan.scannerPath!!
            val started = System.currentTimeMillis()
            val results = mutableListOf<Pair<Drive, DriveOutcome>>()
            for ((i, drive) in drives.withIndex()) {
                if (cancelled || !isActive) {
                    results += drive to DriveOutcome.NotScanned("Stopped before this drive was reached.")
                    continue
                }
                _state.value = FullScanUiState.Running(drives, i, started, results.toList())
                val outcome = FullPcScan.scanDrive(scanner, drive) { handle = it }
                handle = null
                results += drive to if (cancelled) {
                    DriveOutcome.NotScanned("Stopped part-way through, so this drive was not fully read.")
                } else outcome
            }
            _state.value = FullScanUiState.Done(results, System.currentTimeMillis() - started, cancelled)
        }
    }

    fun cancel() {
        cancelled = true
        handle?.cancel()
    }
}
