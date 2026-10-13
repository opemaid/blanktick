# Blanktick sensor - AI content-intake proxy (prompt-injection left half).
#
# Emits one tab-separated line when a process acting as the local AI layer pulls
# from the network - the observable proxy for "the assistant read outside
# content":
#   <epochMillis>\t<pid>\t<image>\t<source>
#
# LIMITS, stated plainly. This is a PROXY, not true intake observation. A
# user-level poll cannot see an assistant reading a local file or receiving
# content inside its own process; it can only see a new outbound connection by a
# process whose IMAGE is a known model runner. So it misses claude.exe, an MCP
# node/python helper, or any agent not in the list below, and it cannot tell a
# model-weight download from a web fetch. Honest, real intake detection needs
# instrumentation of the MCP tool call itself (securing-agentic-ai-tool-
# invocation), which is agent-side, not an OS tap. DYN-AI-003 correlates this
# with a following action; treat a firing as a lead, not proof.
$ErrorActionPreference = 'SilentlyContinue'

# Same known-model-runner set the process tap tags as AI_AGENT.
$agents = @(
    'ollama.exe','ollama app.exe','lmstudio.exe','lm studio.exe',
    'jan.exe','gpt4all.exe','llama-server.exe','koboldcpp.exe','localai.exe'
)
$loopback = @('127.0.0.1','::1','0.0.0.0','::')
$seen = @{}

while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    foreach ($c in Get-NetTCPConnection -State Established) {
        $ra = $c.RemoteAddress
        if ($loopback -contains $ra) { continue }
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        $img = $proc.ProcessName + '.exe'
        if ($img.ToLower() -notin $agents) { continue }
        $key = "$($c.OwningProcess)|$ra|$($c.RemotePort)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        "$now`t$($c.OwningProcess)`t$img`tnet:$ra`:$($c.RemotePort)"
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 1500
}
