# Six things to check on a Windows PC that runs AI tools

*Blanktick · November 2026 · every check below has a PowerShell command you can run yourself*

Antivirus looks for bad files. Most of the risk that AI tools add to a PC is not a file.
It is a setting: a model server that answers anyone on the Wi-Fi, a JSON file that lets
an assistant run commands, an API key pasted into a config two months ago. None of
those trips a virus scanner, and none of them shows up in the places Windows lists
things that start on their own.

Here are the six we check for, why each matters, and how to look by hand. Nothing
below changes anything on your machine. Every command only reads.

The four config files most assistants use on Windows:

| Assistant | File |
|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `%USERPROFILE%\.claude.json` |
| Cursor | `%USERPROFILE%\.cursor\mcp.json` |
| Windsurf | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |

---

## 1. A local model server listening on every network

Ollama, LM Studio, llama.cpp's server and similar tools expose an HTTP API with no
login, because they are meant to answer only this computer. Ollama, for example,
listens on `127.0.0.1` unless you set `OLLAMA_HOST`. Set it to `0.0.0.0`, often done to
reach the model from a phone or another PC, and on a café, hotel or office
network, anyone scanning the subnet gets free use of your GPU, your models, and
whatever is in the conversation.

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } |
  Select-Object LocalPort, @{ n = 'Program'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
  Sort-Object LocalPort -Unique | Format-Table -AutoSize
```

If `ollama`, `LM Studio`, `llama-server`, `koboldcpp`, `open-webui`, `comfyui` or
similar appears in that list, it is reachable from the network. **Fix:** for Ollama,
unset `OLLAMA_HOST` or set it to `127.0.0.1`. Other servers have an equivalent
"listen address" or "serve on local network" setting.

*(Blanktick rule `DSK-AI-001`. It matches by program name, not port, because people
move ports.)*

## 2. An assistant that can run any command

An MCP server entry is a line in a JSON file that tells an assistant "you may start
this program." If that program is `cmd`, `powershell` or `bash`, the assistant can
run anything you can. That is often deliberate. But the file grants it without
showing up in any Run key, scheduled task or service list, which is where every
startup checker looks.

```powershell
$configs = @(
  "$env:APPDATA\Claude\claude_desktop_config.json",
  "$env:USERPROFILE\.claude.json",
  "$env:USERPROFILE\.cursor\mcp.json",
  "$env:USERPROFILE\.codeium\windsurf\mcp_config.json"
) | Where-Object { Test-Path $_ }

& { foreach ($f in $configs) {
  $j = Get-Content $f -Raw | ConvertFrom-Json
  $servers = @($j.mcpServers) + @($j.projects.PSObject.Properties.Value.mcpServers) | Where-Object { $_ }
  foreach ($s in $servers) {
    foreach ($p in $s.PSObject.Properties) {
      [pscustomobject]@{ Tool = $p.Name; Starts = $p.Value.command; File = Split-Path $f -Leaf }
    }
  }
} } | Format-Table -AutoSize
```

Any tool whose `Starts` column is a shell can run commands as you. **Fix:** nothing,
if you recognise it. If you don't, delete the entry from the file shown.

*(Blanktick rule `DSK-AI-002`.)*

## 3. API keys in plain text in those files

Many setup guides tell you to paste an API key into the MCP config. Any program
running as you can then read it. These keys are usually billable and rarely expire.

```powershell
$pattern = 'sk-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{30,}|ghp_[A-Za-z0-9]{30,}'
foreach ($f in $configs) {
  $n = (Select-String -Path $f -Pattern $pattern -AllMatches).Matches.Count
  if ($n) { "{0}: {1} key-shaped value(s)" -f $f, $n }
}
```

This prints file names and counts, never the keys themselves. A checker that copies
your secret into its own output has made the problem worse. **Fix:** move keys
into environment variables or a credential store, and **rotate** any key that sat in
a file. Assume it has been copied.

*(Blanktick rule `DSK-AI-003`.)*

## 4. AI tools that download their code every time they start

Look at the `Starts` column from check 2 again. `npx`, `uvx`, `bunx` and `pipx` don't
name a program on your disk. They fetch a package from a public registry and run
it as you, usually the latest version, every time the assistant starts. If that
package is a look-alike, or is compromised after you added it, the new code runs
with your full access, and nothing on the machine changed for you to notice.

**Fix:** pin a version (`npx some-server@1.4.2`), or install the tool once to a fixed
path and point the config at that.

*(Blanktick rule `DSK-AI-005`.)*

## 5. One assistant that can both read the web and act on your PC

This is the prompt-injection condition. A tool that pulls in outside text (a browser,
fetch, email, Slack, search) is fine alone. A tool that writes files or runs commands
is fine alone. **Together**, a web page or email the assistant reads can carry hidden
instructions, and the assistant has the means to carry them out as you.

It is common. On the first developer PC we checked while writing this, one assistant
had a browser-automation tool started through `npx` next to two tools started through
`cmd`. That is checks 2, 4 and 5 in one config file.

Using the table from check 2: if the same file has a tool named like `fetch`, `web`,
`browser`, `playwright`, `puppeteer`, `search`, `gmail`, `slack` **and** a shell or a
tool named like `filesystem`, `shell`, `exec`, `git`, `docker` or `database`, you have
the pairing. **Fix:** keep content-reading tools and acting tools in separate assistant
profiles, or treat everything the assistant reads as untrusted input.

*(Blanktick rule `DSK-AI-006`. It is a name-based heuristic, and it says so.)*

## 6. Windows Recall keeping a searchable record of your screen

On Copilot+ PCs, Recall periodically snapshots the screen and extracts the text so you
can search it later. That is useful. It is also a searchable history of everything
that was on screen, including things other apps were careful not to store.

```powershell
'Recall off by policy (machine): ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -ErrorAction SilentlyContinue).DisableAIDataAnalysis
'Recall off by policy (user):    ' + (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' -ErrorAction SilentlyContinue).DisableAIDataAnalysis
'Recall snapshot store present:  ' + (Test-Path "$env:LOCALAPPDATA\CoreAIPlatform.00\UKP")
```

`1` means switched off by policy. An empty value means no policy is set. **Fix:** if you
don't use it, *Settings → Privacy & security → Recall & snapshots*.

*(Blanktick rule `DSK-AI-004`. It reports "not applicable" on hardware without Recall.)*

---

## Or let your AI agent do it

[Blanktick](https://blanktick.org) runs these six checks plus about 75 Windows
security settings, offline. It is free and open source (AGPL-3.0), and its build fails
if networking code is ever added. It also tells you which checks it **could not** run,
instead of counting them as passes.

It ships a read-only MCP server, so you can ask your own assistant:

```
/plugin marketplace add opemaid/blanktick
/plugin install blanktick@blanktick
```

> How secure is this PC? Use Blanktick, then give me the three things to fix first and anything you couldn't check.

The tools only read. None of them fixes, deletes or blocks anything: the agent
explains, and you decide.

**Download:** [blanktick.org](https://blanktick.org) · [GitHub](https://github.com/opemaid/blanktick) · `winget install 9MW3G5H3RF3M -s msstore`
