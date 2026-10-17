# Compiled-artifact reverse-engineering audit

An adversarial check that Blanktick's three central promises hold in the
**compiled bytecode**, not just the source. The build-time bytecode gate
(`desktop/build.gradle.kts`, `NoNetworkTest`) already asserts the no-network
property; this is an independent pass over the actual `.class` files
(`*/build/classes/kotlin/main/com/blanktick`, 438 classes), by disassembly
(`javap`) and constant-pool inspection, done 2026-10-17.

## 1. "Never touches the network" — HOLDS

The only classes whose constant pools reference any networking API
(`java/net/Socket`, `URL`, `URLConnection`, `InetAddress`, `openConnection`) are
the `NoNetwork` family:

- `NoNetwork`, `NoNetwork$BlockedSocketImpl`, `$BlockingSocketImplFactory`,
  `$BlockedUrlHandler`, `$LocalOnlyUrlHandlerFactory`, `$BlockedException`.

Disassembly of `NoNetwork.install()` shows it *installs blocking factories* —
`Socket.setSocketImplFactory(...)` and `URL.setURLStreamHandlerFactory(...)` —
so any socket or URL use at runtime throws. These classes **enforce** the
absence of networking; they are not a consumer of it.

Every other class — all rule packs, the collectors, `WindowsProbe`,
`WindowsCollector`, `Shell`, `McpServer`, `Enforcer`, every sensor provider —
has **zero** networking references in its bytecode. No `okhttp3`, `retrofit2`,
`io/ktor`, `SocketChannel`, or `HttpURLConnection` anywhere in the first-party
code. (Third-party jars are covered separately by the build gate's
`auditDependencyNetworkSurface`.)

## 2. "Every operation is read-only" — HOLDS, bounded

Process termination (`ProcessHandle.destroyForcibly` / `destroy`) appears in
exactly four classes, each acting only on a child Blanktick itself started, or
the one documented opt-in action:

- `Shell` — kills the probe's own PowerShell child when it overruns its timeout.
- `WindowsElevation` — kills the admin-check child if it hangs (the bounded wait
  added this session).
- `ScriptTapProvider` — kills its own ETW-tap child on stop.
- `Enforcer` — the opt-in enforcement action, now guarded against kernel-critical
  images (this session).

Filesystem writes (`java/nio/file/Files`, `createTempFile`,
`createTempDirectory`, `deleteOnExit`) appear in exactly two classes — `Shell`
and `ScriptTapProvider` — both of which write their own `.ps1` into a private
temp directory and delete it. No rule, collector, or probe path writes anywhere
on the system.

## 3. "The MCP server exposes only question tools" — HOLDS

The `mcp` package bytecode contains exactly eight tool-name constants —
`blanktick_scan`, `_facts`, `_probe_script`, `_coverage`, `_history`, `_search`,
`_changes`, `_netlog` — matching `docs/mcp.md`. No method in the package carries
a mutating verb (`fix/delete/remove/disable/quarantine/repair/apply/write/
install/set…`). There is no mutation surface in the shipped MCP server.

## Scope / limits

- This audits the compiled Kotlin/JVM classes. It does not disassemble the
  bundled JRE or the WiX/MSI wrapper (not built locally; WiX absent).
- Third-party dependency jars are not re-scanned here; the build gate does that
  and fails the build on a networking reference outside the named exemptions.
- A clean bytecode scan proves the *capability* is absent, which is the strong
  claim; it is complementary to, not a replacement for, the runtime
  `NoNetworkTest` that proves the enforcer actually throws.
