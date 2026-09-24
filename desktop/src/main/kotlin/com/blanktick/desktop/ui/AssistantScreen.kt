package com.blanktick.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.blanktick.desktop.AppState

/**
 * How to point an AI assistant at Blanktick over MCP.
 *
 * There is no button here that "connects", because Blanktick does not connect
 * to anything — it is the MCP *server*, and it opens no socket. The assistant
 * (Claude Desktop, Claude Code, Cursor, …) is the client; it launches
 * `Blanktick.exe --mcp` as a child process and talks to it over that pipe. So
 * the honest, useful thing a screen can do is hand over the exact configuration
 * to paste into the assistant, with this executable's real path already filled
 * in, and a button to copy it.
 */
@Composable
fun AssistantScreen(state: AppState) {
    val c = LocalBlanktickColors.current
    val clip = LocalClipboardManager.current
    var copied by remember { mutableStateOf<String?>(null) }

    // The path the assistant must launch. When Blanktick is a packaged app this
    // resolves to Blanktick.exe; run from a source checkout it will not, so we
    // fall back to the installed location rather than show java.exe.
    val (exe, resolved) = remember {
        val cmd = runCatching { ProcessHandle.current().info().command().orElse(null) }.getOrNull()
        if (cmd != null && cmd.lowercase().endsWith("blanktick.exe")) cmd to true
        else "C:\\Program Files\\Blanktick\\Blanktick.exe" to false
    }

    val json = """
        {
          "mcpServers": {
            "blanktick": {
              "command": "${exe.replace("\\", "\\\\")}",
              "args": ["--mcp"]
            }
          }
        }
    """.trimIndent()
    val cli = "claude mcp add blanktick -- \"$exe\" --mcp"

    // VS Code (GitHub Copilot's MCP, and Cline) use a "servers" object with an
    // explicit transport type rather than the "mcpServers" shape everyone else uses.
    val vscodeJson = """
        {
          "servers": {
            "blanktick": {
              "type": "stdio",
              "command": "${exe.replace("\\", "\\\\")}",
              "args": ["--mcp"]
            }
          }
        }
    """.trimIndent()

    ScrollableColumn(spacing = BlanktickTokens.Space.s4) {
        Text("Connect an assistant", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        Text(
            "Any assistant that speaks MCP can query this computer's security posture and get " +
                "real answers instead of guesses — and it works regardless of the model behind " +
                "the assistant: Claude, GPT, Gemini, or a local model through Ollama. Blanktick " +
                "is the server; the assistant launches it and reads its replies over a local " +
                "pipe. No socket is opened, nothing is bound, and the build still fails if any " +
                "networking code is added. The configuration is nearly identical everywhere — " +
                "usually only the file it goes in changes.",
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted,
            modifier = Modifier.widthIn(max = 680.dp)
        )

        if (!resolved) {
            Notice(
                "You are running Blanktick from a source checkout, so the path below is the " +
                    "default install location. Point it at wherever your Blanktick.exe actually is."
            )
        }

        SectionHeader("Most clients — Claude Desktop, Cursor, Windsurf, Cline")
        ConfigBlock(
            subtitle = "The same \"mcpServers\" block. It goes in each client's own config file:\n" +
                "  • Claude Desktop — %APPDATA%\\Claude\\claude_desktop_config.json\n" +
                "  • Cursor — %USERPROFILE%\\.cursor\\mcp.json (or .cursor\\mcp.json in a project)\n" +
                "  • Windsurf — %USERPROFILE%\\.codeium\\windsurf\\mcp_config.json\n" +
                "Restart the client afterwards.",
            body = json,
            copiedLabel = if (copied == "json") "Copied" else "Copy config"
        ) { clip.setText(AnnotatedString(json)); copied = "json" }

        SectionHeader("VS Code (GitHub Copilot / Cline)")
        ConfigBlock(
            subtitle = "VS Code uses a \"servers\" block with an explicit transport. Put it in " +
                ".vscode\\mcp.json in your workspace.",
            body = vscodeJson,
            copiedLabel = if (copied == "vscode") "Copied" else "Copy config"
        ) { clip.setText(AnnotatedString(vscodeJson)); copied = "vscode" }

        SectionHeader("Claude Code")
        ConfigBlock(
            subtitle = "Run once in a terminal.",
            body = cli,
            copiedLabel = if (copied == "cli") "Copied" else "Copy command"
        ) { clip.setText(AnnotatedString(cli)); copied = "cli" }

        Text(
            "Any other MCP client works the same way: give it the command \"$exe\" with the " +
                "argument --mcp over stdio. MCP clients evolve, so if a file path or key name " +
                "differs in your version, check that client's own MCP documentation — the " +
                "command and argument do not change.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint,
            modifier = Modifier.widthIn(max = 680.dp)
        )

        SectionHeader("What this grants")
        Card {
            Text(
                "Read-only access to this machine's security posture. Every tool is a question — " +
                    "nothing an assistant can call through Blanktick changes a setting, removes a " +
                    "file, or fixes a finding. It surveys and recommends; you decide and act.",
                style = MaterialTheme.typography.bodyLarge,
                color = c.inkMuted
            )
            Hairline()
            Text(
                "Blanktick's own rule DSK-AI-002 warns that an MCP entry lets a model run the " +
                    "commands it is configured with, and that such entries appear in none of the " +
                    "usual startup locations. That is true of this one too. Add it deliberately, " +
                    "and only for an assistant you trust.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkFaint,
                modifier = Modifier.widthIn(max = 680.dp)
            )
        }
    }
}

@Composable
private fun ConfigBlock(
    subtitle: String,
    body: String,
    copiedLabel: String,
    onCopy: () -> Unit
) {
    val c = LocalBlanktickColors.current
    Card {
        Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
        Hairline()
        SelectionContainer {
            Surface(
                color = c.surfaceSunk,
                shape = RoundedCornerShape(BlanktickTokens.Radius.md),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(body, style = LedgerNumberStyle, color = c.ink, modifier = Modifier.padding(14.dp))
            }
        }
        Spacer(Modifier.height(BlanktickTokens.Space.s2))
        Row(horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s2)) {
            PrimaryButton(copiedLabel, onClick = onCopy)
        }
    }
}
