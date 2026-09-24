package com.blanktick.app.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blanktick.app.ScanViewModel
import com.blanktick.app.Tab

/**
 * The app shell.
 *
 * Five destinations in a bottom bar, and no navigation library: the graph is a
 * flat set of five peers with no arguments and no back stack worth preserving,
 * so `androidx.navigation` would be a dependency earning nothing. Decision D-03
 * says every third-party artifact in a security app has to justify itself, and
 * this one cannot.
 */
@Composable
fun BlanktickApp(viewModel: ScanViewModel) {
    val c = LocalBlanktickColors.current
    val tab by viewModel.tab.collectAsStateWithLifecycle()
    val state by viewModel.state.collectAsStateWithLifecycle()

    Surface(Modifier.fillMaxSize(), color = c.paper) {
        Scaffold(
            containerColor = c.paper,
            bottomBar = {
                NavigationBar(containerColor = c.surface) {
                    Tab.entries.forEach { destination ->
                        NavigationBarItem(
                            selected = destination == tab,
                            onClick = { viewModel.show(destination) },
                            // Text rather than icons: five abstract glyphs would
                            // need learning, and "Passwords" needs none. The
                            // design gate checklist prefers a label it can read
                            // at 200% font scale over an icon it cannot.
                            icon = {
                                Text(
                                    destination.tabLabel,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (destination == tab) c.ink else c.inkMuted,
                                    maxLines = 1
                                )
                            },
                            colors = NavigationBarItemDefaults.colors(
                                indicatorColor = c.kelpTint
                            )
                        )
                    }
                }
            }
        ) { padding ->
            Box(Modifier.fillMaxSize()) {
                when (tab) {
                    Tab.SCAN -> HomeScreen(
                        state = state,
                        onScan = viewModel::scan,
                        padding = padding
                    )
                    Tab.LINK -> LinkScreen(viewModel, padding)
                    Tab.PASSWORDS -> PasswordScreen(viewModel, padding)
                    Tab.PHOTOS -> PhotoScreen(viewModel, padding)
                    Tab.ABOUT -> AboutScreen(viewModel, padding)
                }
            }
        }
    }
}
