package com.blanktick.desktop.report

import com.blanktick.core.ScanReport
import com.blanktick.core.model.Grade
import com.blanktick.core.model.Severity

/**
 * Renders a scan into a single self-contained HTML dashboard.
 *
 * The file loads no webfont and makes no request — same rule the marketing site
 * keeps, so a reader who opens the network tab on a report about their own
 * machine finds it silent. It is generated on demand by `--report` and written
 * where the user asks; like the scan history, it is a picture of the machine's
 * weaknesses, so it is theirs to place and delete, not something the app keeps.
 *
 * Every value that came off the machine is HTML-escaped: a program name or a
 * finding detail is attacker-influenced text, and a report is exactly where an
 * unescaped `<` would matter.
 */
object ReportHtml {

    data class Provenance(
        val os: String,
        val scannedAt: String,
        val avSubmitted: Int?,   // null: no scanner was available to ask
        val avFlagged: Int,
        val hashNote: String,
        val intelDate: String?,
        val intelSynthetic: Boolean
    )

    fun render(report: ScanReport, p: Provenance): String {
        val r = report.result
        val gradeHex = gradeColor(r.grade)
        val arc = 270.0 * r.score / 100.0
        val total = r.findings.sumOf { it.deduction }
        val wrong = report.skippedWrongPlatform.size
        val unobs = report.skippedUnobservable.size

        val findings = r.actionableFindings.sortedByDescending { it.deduction }.joinToString("\n") { sf ->
            val f = sf.finding
            val sev = f.severity.name
            val hex = severityColor(f.severity)
            """
            <div class="finding">
              <div class="sevbar" style="background:$hex"></div>
              <div class="fbody">
                <div class="frow">
                  <span class="chip" style="color:$hex">$sev</span>
                  <span class="rid">${esc(f.ruleId)}</span>
                  <span class="ded" style="color:$hex">&minus;${sf.deduction}</span>
                </div>
                <div class="ftitle">${esc(f.title)}</div>
                <div class="fnote">${esc(f.remediation.ifBlank { f.detail })}</div>
              </div>
            </div>
            """.trimIndent()
        }.ifBlank {
            """<div class="fnote" style="padding:8px 0">No findings in what was checked. Read that
               next to coverage — it means nothing was found to deduct for, not that everything is
               fine.</div>""".trimIndent()
        }

        val avRow = if (p.avSubmitted != null)
            provRow("&#10003;", "ok", "Antivirus",
                "${p.avSubmitted} files submitted to the installed scanner, read-only &middot; " +
                    "${p.avFlagged} flagged")
        else provRow("&#8226;", "", "Antivirus", "No scanner was available to ask")

        val intelRow = if (p.intelSynthetic)
            provRow("!", "warn", "Threat data",
                "<b style=\"color:var(--med)\">SYNTHETIC</b>" +
                    (p.intelDate?.let { " (built ${esc(it)})" } ?: "") +
                    " &mdash; password &amp; link checks are demonstrations, not real protection yet")
        else provRow("&#10003;", "ok", "Threat data",
            "Loaded" + (p.intelDate?.let { " (built ${esc(it)})" } ?: ""))

        return TEMPLATE
            .replace("{{OS}}", esc(p.os))
            .replace("{{WHEN}}", esc(p.scannedAt))
            .replace("{{SCORE}}", r.score.toString())
            .replace("{{GRADE}}", esc(r.grade.label))
            .replace("{{GRADEHEX}}", gradeHex)
            .replace("{{ARC}}", fmt(arc))
            .replace("{{ARCGAP}}", fmt(360.0 - arc))
            .replace("{{RAN}}", r.checksRun.toString())
            .replace("{{SKIP}}", r.checksSkipped.toString())
            .replace("{{WRONG}}", wrong.toString())
            .replace("{{UNOBS}}", unobs.toString())
            .replace("{{NFIND}}", r.actionableFindings.size.toString())
            .replace("{{TOTAL}}", total.toString())
            .replace("{{FINDINGS}}", findings)
            .replace("{{AVROW}}", avRow)
            .replace("{{HASHNOTE}}", esc(p.hashNote))
            .replace("{{INTELROW}}", intelRow)
    }

    private fun provRow(mark: String, cls: String, label: String, value: String) =
        """<div class="prow"><span class="pmark $cls">$mark</span>
           <span class="plabel">$label</span><span class="pval">$value</span></div>""".trimIndent()

    private fun gradeColor(g: Grade) = when (g) {
        Grade.STRONG, Grade.GOOD -> "#5FBFA3"
        Grade.FAIR -> "#D9BC4B"
        Grade.WEAK -> "#F0A467"
        Grade.AT_RISK -> "#F0907E"
    }

    private fun severityColor(s: Severity) = when (s) {
        Severity.CRITICAL -> "#F0907E"
        Severity.HIGH -> "#F0A467"
        Severity.MEDIUM -> "#D9BC4B"
        Severity.LOW -> "#A3B0C4"
        Severity.INFO -> "#9FB0BF"
    }

    private fun fmt(d: Double) = ((d * 10).toInt() / 10.0).toString()

    private fun esc(s: String) = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private val TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blanktick &mdash; This computer</title>
<style>
  :root{
    --paper:#0C0E0D; --surface:#151817; --sunk:#101312; --line:#222724;
    --ink:#F2F1ED; --muted:#9AA19E; --faint:#7A827E; --good:#5FBFA3;
    --crit:#F0907E; --high:#F0A467; --med:#D9BC4B; --low:#A3B0C4;
    --sans:-apple-system,"Segoe UI",Roboto,system-ui,sans-serif;
    --mono:"Cascadia Code","Consolas",ui-monospace,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
    -webkit-font-smoothing:antialiased;line-height:1.5}
  .wrap{max-width:1180px;margin:0 auto;padding:32px 28px 56px}
  .num{font-family:var(--mono);font-variant-numeric:tabular-nums}
  header{display:flex;justify-content:space-between;align-items:flex-end;
    border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
  .brand{font-size:26px;font-weight:700;letter-spacing:-.01em}
  .brand small{display:block;font-size:12px;font-weight:500;color:var(--faint);
    letter-spacing:.02em;margin-top:4px}
  .meta{text-align:right;font-size:12.5px;color:var(--muted)}
  .meta .num{color:var(--ink)}
  .grid{display:grid;grid-template-columns:360px 1fr;gap:24px;align-items:start}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:22px}
  .card h2{margin:0 0 14px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;
    color:var(--faint);font-weight:700}
  .gaugeCard{display:flex;flex-direction:column;align-items:center;gap:2px}
  .gaugeWrap{position:relative;width:300px;height:300px}
  .gaugeWrap svg{width:300px;height:300px;transform:translateY(6px)}
  .gaugeNum{position:absolute;inset:0;display:flex;flex-direction:column;
    align-items:center;justify-content:center;pointer-events:none;transform:translateY(-6px)}
  .gaugeNum b{font-family:var(--mono);font-size:76px;font-weight:600;line-height:1;
    color:var(--ink);font-variant-numeric:tabular-nums}
  .gaugeNum b i{font-style:normal;font-size:30px;color:var(--faint)}
  .grade{margin-top:10px;font-size:13px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
  .gaugeNote{font-size:12px;color:var(--faint);text-align:center;max-width:240px;margin-top:2px}
  .tiles{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:16px}
  .tile{background:var(--sunk);border:1px solid var(--line);border-radius:12px;padding:14px 12px;text-align:center}
  .tile b{display:block;font-family:var(--mono);font-size:30px;font-weight:600;color:var(--ink)}
  .tile span{display:block;font-size:11px;color:var(--muted);margin-top:3px}
  .cov{margin-top:16px}
  .covBar{display:flex;height:16px;border-radius:8px;overflow:hidden;border:1px solid var(--line)}
  .covRan{background:var(--good)}
  .covSkip{background:repeating-linear-gradient(45deg,#3a403d 0 5px,#2b302e 5px 10px)}
  .covKey{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-top:8px}
  .covKey .num{color:var(--ink)}
  .fhead{display:flex;align-items:center;gap:10px;margin:0 0 6px}
  .fhead h2{margin:0}
  .fcount{font-family:var(--mono);font-size:12px;color:var(--faint)}
  .finding{display:flex;gap:14px;padding:16px 0;border-top:1px solid var(--line)}
  .finding:first-of-type{border-top:none}
  .sevbar{width:4px;border-radius:2px;flex:none}
  .fbody{flex:1;min-width:0}
  .frow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .chip{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.06em;
    padding:2px 7px;border-radius:5px;border:1px solid currentColor}
  .rid{font-family:var(--mono);font-size:12px;color:var(--faint)}
  .ded{margin-left:auto;font-family:var(--mono);font-size:15px;font-weight:600}
  .ftitle{margin:5px 0 3px;font-size:15.5px;color:var(--ink);font-weight:600}
  .fnote{font-size:13px;color:var(--muted)}
  .prov{margin-top:24px}
  .prow{display:flex;align-items:flex-start;gap:12px;padding:11px 0;border-top:1px solid var(--line);font-size:14px}
  .prow:first-of-type{border-top:none}
  .pmark{font-family:var(--mono);font-weight:700;flex:none;width:18px;text-align:center}
  .ok{color:var(--good)} .warn{color:var(--med)}
  .plabel{color:var(--ink);font-weight:600;min-width:132px}
  .pval{color:var(--muted)}
  footer{margin-top:28px;padding-top:18px;border-top:1px solid var(--line);
    font-size:12.5px;color:var(--faint);max-width:820px}
  footer b{color:var(--muted);font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">Blanktick<small>OFFLINE &middot; NOTHING LEAVES THIS COMPUTER</small></div>
    <div class="meta">This computer &middot; <span class="num">{{OS}}</span><br>scanned <span class="num">{{WHEN}}</span></div>
  </header>
  <div class="grid">
    <div>
      <div class="card gaugeCard">
        <div class="gaugeWrap">
          <svg viewBox="0 0 320 320" aria-hidden="true">
            <circle cx="160" cy="160" r="120" pathLength="360" fill="none"
              stroke="#1d2320" stroke-width="16" stroke-linecap="round"
              stroke-dasharray="270 90" transform="rotate(135 160 160)"/>
            <circle cx="160" cy="160" r="120" pathLength="360" fill="none"
              stroke="{{GRADEHEX}}" stroke-width="16" stroke-linecap="round"
              stroke-dasharray="{{ARC}} {{ARCGAP}}" transform="rotate(135 160 160)"/>
          </svg>
          <div class="gaugeNum"><b>{{SCORE}}<i>/100</i></b></div>
        </div>
        <div class="grade" style="color:{{GRADEHEX}}">{{GRADE}}</div>
        <div class="gaugeNote">A score is deductions from 100 &mdash; read it next to coverage below.</div>
      </div>
      <div class="tiles">
        <div class="tile"><b>{{RAN}}</b><span>checks ran</span></div>
        <div class="tile"><b>{{SKIP}}</b><span>not checkable</span></div>
        <div class="tile"><b>{{NFIND}}</b><span>findings</span></div>
      </div>
      <div class="card cov">
        <h2>Coverage</h2>
        <div class="covBar">
          <div class="covRan" style="flex:{{RAN}}"></div>
          <div class="covSkip" style="flex:{{SKIP}}"></div>
        </div>
        <div class="covKey"><span><span class="num">{{RAN}}</span> ran</span>
          <span><span class="num">{{SKIP}}</span> not checkable</span></div>
        <div class="covKey" style="margin-top:4px;color:var(--faint)">
          <span>{{WRONG}} wrong device</span><span>{{UNOBS}} wouldn&rsquo;t answer</span></div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="fhead"><h2 style="text-transform:uppercase">Needs attention</h2>
          <span class="fcount">{{NFIND}} findings &middot; &minus;{{TOTAL}} total</span></div>
        {{FINDINGS}}
      </div>
      <div class="card prov">
        <h2>What was checked</h2>
        {{AVROW}}
        <div class="prow"><span class="pmark ok">&#10003;</span>
          <span class="plabel">Malware hashes</span><span class="pval">{{HASHNOTE}}</span></div>
        {{INTELROW}}
      </div>
    </div>
  </div>
  <footer>
    <b>How to read this.</b> The score is deductions subtracted from 100, so it only means something
    beside coverage: {{SKIP}} checks could not run, so the number partly reflects what wasn&rsquo;t
    inspected. &ldquo;Not checkable&rdquo; is never a pass &mdash; Blanktick reports what it could not
    see rather than assuming it is fine. Nothing here left this computer, and the app opened no socket
    to produce it.
  </footer>
</div>
</body>
</html>
    """.trimIndent()
}
