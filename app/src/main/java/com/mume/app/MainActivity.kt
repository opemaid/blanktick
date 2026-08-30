package com.mume.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.mume.app.ui.MumeApp
import com.mume.app.ui.MumeTheme

class MainActivity : ComponentActivity() {

    private val viewModel: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        handleSharedLink(intent)

        setContent {
            MumeTheme {
                MumeApp(viewModel)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleSharedLink(intent)
    }

    /**
     * A link arriving from the share sheet is analysed locally and immediately,
     * and the view model switches to the link tab so the result is visible.
     * Receiving a shared link requires no network permission, and neither does
     * checking it.
     */
    private fun handleSharedLink(intent: Intent?) {
        if (intent?.action != Intent.ACTION_SEND) return
        intent.getStringExtra(Intent.EXTRA_TEXT)?.let(viewModel::checkLink)
    }
}
