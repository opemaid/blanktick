"""Emits the "Claude + Blanktick, a real session" replay video.

Source of truth: capture/session.jsonl, a real `claude -p --output-format
stream-json` run on 2026-10-29 with the plugins/blanktick plugin (kept local,
see .gitignore). What the replay changes, and says on screen that it changes:
  - the ~100 s scan wait is shortened;
  - Claude's answer is shortened to its headings, rule ids and Blanktick's own
    fix text;
  - machine specifics are redacted (the DNS server address).
Everything else — the prompt, the tool sequence, the numbers, the rule ids,
the wording quoted — is copied from the capture.
"""
import pathlib

ROOT = pathlib.Path(__file__).parent
FRAMES = ROOT / "compositions" / "frames"
FRAMES.mkdir(parents=True, exist_ok=True)

SCENES = [("s1", 4.5), ("s2", 14.0), ("s3", 10.0), ("s4", 17.0), ("s5", 10.0), ("s6", 7.0)]

PROMPT = ("How secure is this PC? Use Blanktick to check, then give me the three things "
          "I should fix first and anything you couldn't check.")

CSS = """
@font-face{font-family:"bt-ui";src:local("Segoe UI"),local("SegoeUI");font-weight:400}
@font-face{font-family:"bt-ui";src:local("Segoe UI Semibold"),local("SegoeUI-Semibold");font-weight:600}
@font-face{font-family:"bt-mono";src:local("Cascadia Mono"),local("Consolas")}
@font-face{font-family:"bt-ui";src:local("Segoe UI Bold"),local("SegoeUI-Bold");font-weight:700}
#root{position:relative;width:1920px;height:1080px;overflow:hidden;background:#FAF9F6;container-type:size;font-family:"bt-ui","Segoe UI",sans-serif;color:#0B0D0C}
.wrap{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;padding:3.2cqw 7cqw}
.mono{font-family:"bt-mono",monospace}
.k{color:#0F4D3F}.c{color:#C2613F}
.win{background:#141615;border-radius:16px;overflow:hidden;box-shadow:0 0 0 1.5px rgba(15,77,63,.25)}
.bar{display:flex;align-items:center;gap:.6cqw;padding:.8cqw 1.2cqw;background:#1E211F;color:#9AA19E;font-size:.9cqw}
.dot{width:.75cqw;height:.75cqw;border-radius:50%;background:#3A3F3C}
.body{padding:1.4cqw 1.8cqw;color:#E8EAE9;font-size:1.15cqw;line-height:1.6}
.ln{opacity:0;white-space:pre-wrap}
.me{color:#FAF9F6}.me b{color:#7FD3B8}
.bul{color:#E9A27F}
.dim{color:#8C9390}
.tool{color:#7FD3B8;font-weight:700}
.cap{position:absolute;left:7cqw;bottom:2.2cqw;font-size:1cqw;color:#5A6260;opacity:0}
.chip{display:inline-block;padding:.35cqw .9cqw;border-radius:100px;background:rgba(15,77,63,.08);border:1.5px solid rgba(15,77,63,.2);color:#0F4D3F;font-weight:600;font-size:.95cqw}
.ch{opacity:0}
"""


def scene(sid, dur, css, body, js):
    return f"""<template>
  <div id="root" data-composition-id="{sid}" data-start="0" data-duration="{dur}" data-width="1920" data-height="1080">
    <style>{CSS}{css}</style>
    <div class="wrap clip" id="{sid}-wrap" data-start="0" data-duration="{dur}" data-track-index="0">
{body}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
    <script>
      (function(){{
        window.__timelines = window.__timelines || {{}};
        var tl = gsap.timeline({{ paused: true }});
        function up(sel, t, d){{ tl.fromTo(sel, {{opacity:0, y:12}}, {{opacity:1, y:0, duration:d||0.4, ease:"power2.out"}}, t); }}
        function pop(sel, t){{ tl.fromTo(sel, {{opacity:0, scale:0.94}}, {{opacity:1, scale:1, duration:0.32, ease:"back.out(2)"}}, t); }}
        function lines(sel, t, step){{ var ls = document.querySelectorAll(sel); for (var i = 0; i < ls.length; i++) tl.fromTo(ls[i], {{opacity:0}}, {{opacity:1, duration:0.18}}, t + i*step); }}
{js}
        tl.set({{}}, {{}}, {dur});
        window.__timelines["{sid}"] = tl;
      }})();
    </script>
  </div>
</template>
"""


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def typed(text):
    return "".join(f'<span class="ch">{esc(c)}</span>' for c in text)


def win(title, inner, extra_id="w"):
    return (f'<div class="win" id="{extra_id}"><div class="bar"><span class="dot"></span><span class="dot"></span>'
            f'<span class="dot"></span><span style="margin-left:.6cqw">{title}</span></div><div class="body mono">{inner}</div></div>')


S = {}

# ---- S1 title -----------------------------------------------------------------
S["s1"] = scene("s1", 4.5, """
#e{font-size:1cqw;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#0F4D3F;opacity:0}
#t{font-size:4cqw;font-weight:700;letter-spacing:-.02em;line-height:1.1;margin-top:.8cqw;opacity:0}
#u{font-size:1.4cqw;color:#5A6260;margin-top:1.2cqw;opacity:0}
""", """
      <div id="e">A real session &middot; recorded 29 October 2026</div>
      <div id="t"><span class="c">Claude</span> checks a PC<br>with <span class="k">Blanktick</span></div>
      <div id="u">One question. One scan. Nothing changed on the machine.</div>
""", """
        up("#e", 0.1); up("#t", 0.3, 0.55); up("#u", 1.1);
""")

# ---- S2 prompt, skill, scan call ---------------------------------------------
s2_inner = (
    f'<div class="ln me" id="pl"><b>&gt;</b> {typed(PROMPT)}</div>'
    '<div class="ln" style="margin-top:1cqw"><span class="bul">&#9679;</span> <span class="tool">Skill</span>(blanktick:security-checkup)</div>'
    '<div class="ln dim">&nbsp;&nbsp;&#9492; Launching skill: blanktick:security-checkup</div>'
    '<div class="ln" style="margin-top:.8cqw"><span class="bul">&#9679;</span> Running the full Blanktick scan now. It takes about 100 seconds.</div>'
    '<div class="ln" style="margin-top:.8cqw"><span class="bul">&#9679;</span> <span class="tool">blanktick - blanktick_scan</span> (MCP)</div>'
    '<div class="ln dim" id="run">&nbsp;&nbsp;&#9492; running&hellip; <span id="secs">0</span> s</div>'
)
S["s2"] = scene("s2", 14.0, """
#w{margin-top:.5cqw}
#note{margin-top:1.2cqw;opacity:0}
""", f"""
      {win("Claude Code &mdash; with the Blanktick plugin", s2_inner)}
      <div id="note"><span class="chip">The real scan took about 100 seconds &mdash; shortened here</span></div>
""", f"""
        up("#w", 0.1, 0.35);
        tl.set("#pl", {{opacity:1}}, 0.4);
        var ch = document.querySelectorAll("#pl .ch");
        for (var i = 0; i < ch.length; i++) tl.set(ch[i], {{opacity:1}}, 0.5 + i*0.026);
        var t0 = 0.5 + ch.length*0.026 + 0.4;
        var ls = document.querySelectorAll("#s2-wrap .ln");
        for (var j = 1; j < ls.length; j++) tl.fromTo(ls[j], {{opacity:0}}, {{opacity:1, duration:0.2}}, t0 + (j-1)*0.9);
        var tRun = t0 + (ls.length-2)*0.9;
        var counter = {{v:0}};
        tl.to(counter, {{v:100, duration:4.2, ease:"none", onUpdate:function(){{ document.getElementById("secs").textContent = Math.round(counter.v); }}}}, tRun + 0.2);
        up("#note", tRun + 0.4);
""")

# ---- S3 the tool result (verbatim header + finding titles; IP redacted) -------
res = [
    ("hd", "BLANKTICK SCAN"),
    ("dim", "============================================================"),
    ("", "checks run:    57"),
    ("", "not checkable: 31 (18 not written for this kind of device, 13 this machine would not answer)"),
    ("", "score:         67/100 (FAIR)"),
    ("dim", "A score is deductions subtracted from 100, so it is only meaningful"),
    ("dim", "alongside the coverage above."),
    ("", " "),
    ("hd", "FINDINGS (10):"),
    ("med", "[MEDIUM] NET-DNS-001  Name lookups go to an unrecognised server   (-9)"),
    ("dim", "  what:  This network directs your DNS queries to [address redacted], which is neither your router nor a well-known public resolver."),
    ("med", "[MEDIUM] DSK-EXT-001  “McAfee WebAdvisor” in Brave did not come from the store   (-9)"),
    ("med", "[MEDIUM] DSK-EXT-001  “McAfee WebAdvisor” in Chrome did not come from the store   (-5)"),
    ("low", "[LOW] DSK-NET-003  This computer shouts network lookups to whoever is listening   (-3)"),
    ("low", "[LOW] DSK-AI-002  2 AI assistant tools can run commands here   (-0)"),
    ("dim", "  … 5 more"),
]
s3_inner = "".join(
    f'<div class="ln {c}">{esc(t) if t.strip() else "&nbsp;"}</div>' for c, t in res
).replace("[address redacted]", '<span class="red">[address redacted]</span>')
S["s3"] = scene("s3", 10.0, """
.body{font-size:1.02cqw;line-height:1.55}
.hd{color:#7FD3B8;font-weight:700}.med{color:#E9C46A}.low{color:#CBD2CF}
.red{background:#3A3F3C;color:#FAF9F6;padding:0 .3cqw;border-radius:4px}
#lab{margin-bottom:.9cqw;opacity:0}
""", f"""
      <div id="lab"><span class="chip">What Blanktick sent back &mdash; verbatim, one address redacted</span></div>
      {win("blanktick_scan &rarr; result (7,754 characters)", s3_inner)}
""", """
        up("#lab", 0.05); up("#w", 0.2, 0.3);
        lines("#s3-wrap .ln", 0.5, 0.34);
""")

# ---- S4 Claude's answer: coverage first, then the three fixes -----------------
fixes = [
    ("1", "NET-DNS-001", "Medium", "DNS lookups go to a server Blanktick doesn’t recognise",
     "“Turn on Private DNS with a resolver you trust, or leave this network.”",
     "Check first whether a VPN, antivirus or work tool set this on purpose."),
    ("2", "DSK-EXT-001", "Medium · 6 found", "Browser extensions that didn’t come from the store",
     "“Confirm you deliberately added it, and remove it if you did not.”",
     "Biggest: McAfee WebAdvisor in Brave (−9) and Chrome (−5)."),
    ("3", "DSK-NET-003", "Low", "Windows broadcasts name lookups to the local network",
     "Turn off LLMNR and NetBIOS over TCP/IP.",
     "“This rarely breaks anything on a home network.”"),
]
cards = "".join(
    f'<div class="fx card" id="fx{i}"><div class="num">{n}</div><div class="fb">'
    f'<div class="fr mono">{rid} &middot; {sev}</div><div class="ft">{esc(t)}</div>'
    f'<div class="ff"><b>Blanktick&rsquo;s fix:</b> {esc(f)}</div><div class="fn">{esc(note)}</div></div></div>'
    for i, (n, rid, sev, t, f, note) in enumerate(fixes)
)
S["s4"] = scene("s4", 17.0, """
.who{font-size:.95cqw;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#A8502F;opacity:0}
#lead{font-size:1.6cqw;line-height:1.45;margin-top:.6cqw;max-width:80cqw;opacity:0}
#lead b{color:#0F4D3F}
#fxs{display:grid;grid-template-columns:repeat(3,1fr);gap:1.2cqw;margin-top:1.8cqw}
.card{background:rgba(15,77,63,.04);border:1.5px solid rgba(15,77,63,.2);border-radius:14px}
.fx{display:flex;gap:1cqw;padding:1.3cqw;opacity:0}
.num{flex:none;width:2.4cqw;height:2.4cqw;border-radius:50%;background:#0F4D3F;color:#FAF9F6;font-weight:700;font-size:1.2cqw;display:flex;align-items:center;justify-content:center}
.fr{font-size:.85cqw;color:#666D6B;font-weight:600}
.ft{font-size:1.25cqw;font-weight:700;margin-top:.3cqw;line-height:1.3}
.ff{font-size:1cqw;color:#0B0D0C;margin-top:.7cqw;line-height:1.45}
.fn{font-size:.95cqw;color:#5A6260;margin-top:.5cqw;line-height:1.45}
""", f"""
      <div class="who" id="who">Claude&rsquo;s answer &mdash; shortened</div>
      <div id="lead">The score is <b>67/100 (FAIR)</b>, but read it alongside the coverage. <b>57 checks ran and 31 did not.</b> Nothing came back Critical or High.</div>
      <div id="fxs">{cards}</div>
""", """
        up("#who", 0.1); up("#lead", 0.4, 0.5);
        for (var i = 0; i < 3; i++) pop("#fx"+i, 2.6 + i*2.6);
""")

# ---- S5 what could not be checked ---------------------------------------------
unk = [
    ("ACC-LOCK-001", "Screen lock strength"), ("DSK-LOCK-001", "Password on wake"),
    ("DSK-MAL-004", "Known-malware file match"), ("DSK-REP-001", "SmartScreen on downloads"),
    ("DSK-VBS-002", "Credential Guard"), ("DSK-AI-004", "Windows Recall"),
    ("NET-WIFI-001", "Wi-Fi encryption"), ("ACC-PWD-001", "Breached saved passwords"),
]
chips = "".join(f'<div class="u card" id="u{i}"><div class="ur mono">{r}</div><div class="ut">{t}</div></div>'
                for i, (r, t) in enumerate(unk))
S["s5"] = scene("s5", 10.0, """
.h{font-size:2.4cqw;font-weight:700;letter-spacing:-.02em;opacity:0}
.s{font-size:1.3cqw;color:#5A6260;margin-top:.6cqw;opacity:0}
#us{display:grid;grid-template-columns:repeat(4,1fr);gap:1cqw;margin-top:1.8cqw}
.card{background:rgba(102,109,107,.06);border:1.5px dashed rgba(102,109,107,.45);border-radius:12px}
.u{padding:1cqw 1.2cqw;opacity:0}
.ur{font-size:.85cqw;color:#666D6B;font-weight:600}
.ut{font-size:1.2cqw;font-weight:600;margin-top:.3cqw}
#more{font-size:1.05cqw;color:#5A6260;margin-top:1.2cqw;opacity:0}
""", f"""
      <div class="h" id="h5">What couldn&rsquo;t be checked <span class="c">&mdash; these are not passes</span></div>
      <div class="s" id="s5s">Claude listed the 13 checks Windows wouldn&rsquo;t answer, instead of rounding them up to &ldquo;fine&rdquo;.</div>
      <div id="us">{chips}</div>
      <div id="more">&hellip; and 5 more. Claude also spotted that a macOS-only check was mislabelled on Windows.</div>
""", """
        up("#h5", 0.1, 0.5); up("#s5s", 0.6);
        for (var i = 0; i < 8; i++) pop("#u"+i, 1.6 + i*0.45);
        up("#more", 5.6);
""")

# ---- S6 the receipt + end card ------------------------------------------------
S["s6"] = scene("s6", 7.0, """
.wrap{align-items:center;text-align:center}
#stats{display:flex;gap:1.6cqw;opacity:0}
.st{padding:1.2cqw 2cqw;background:rgba(15,77,63,.04);border:1.5px solid rgba(15,77,63,.2);border-radius:14px}
.sv{font-size:3cqw;font-weight:700;color:#0F4D3F}
.sl{font-size:1cqw;color:#5A6260;margin-top:.2cqw}
#line{font-size:1.9cqw;font-weight:700;margin-top:2.4cqw;opacity:0}
#url{font-size:1.5cqw;font-weight:700;color:#0F4D3F;margin-top:1.4cqw;opacity:0}
""", """
      <div id="stats">
        <div class="st"><div class="sv">1</div><div class="sl">skill loaded</div></div>
        <div class="st"><div class="sv">1</div><div class="sl">Blanktick tool call</div></div>
        <div class="st"><div class="sv">0</div><div class="sl">settings changed</div></div>
        <div class="st"><div class="sv">3m 42s</div><div class="sl">whole session</div></div>
      </div>
      <div id="line"><span class="c">Claude</span> advised. <span class="k">You</span> decide what to fix.</div>
      <div id="url">Blanktick &middot; free &amp; offline &middot; blanktick.org</div>
""", """
        pop("#stats", 0.2); up("#line", 1.6, 0.5); up("#url", 2.6);
""")

for sid, _ in SCENES:
    (FRAMES / f"{sid}.html").write_text(S[sid], encoding="utf-8")

t = 0.0
divs, cuts = [], []
for i, (sid, dur) in enumerate(SCENES):
    divs.append(f'      <div id="el-{sid}" class="scene" data-composition-id="{sid}" data-composition-src="compositions/frames/{sid}.html" data-start="{t:.1f}" data-duration="{dur}" data-track-index="{i % 2}"></div>')
    cuts.append(f'      cut("#el-{sid}", {t:.1f}, {dur});')
    t += dur
total = round(t, 1)

index = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=1920, height=1080" />
    <script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js" integrity="sha384-sG0Hv1tP1lZCk9KQmrIbY/XNwi+OY84GQqhMscbnsoBFqAz8KNCil1kvfL3Hbbk2" crossorigin="anonymous"></script>
    <style>
      * {{ margin: 0; padding: 0; box-sizing: border-box; }}
      html, body {{ width: 1920px; height: 1080px; overflow: hidden; background: #000; }}
      #root {{ position: relative; width: 1920px; height: 1080px; overflow: hidden; background: #FAF9F6; }}
      .scene {{ position: absolute; inset: 0; width: 100%; height: 100%; }}
    </style>
  </head>
  <body>
    <div id="root" data-composition-id="main" data-start="0" data-duration="{total}" data-width="1920" data-height="1080">
{chr(10).join(divs)}

      <audio id="el-bgm1" src="assets/bgm/track.wav" data-start="0" data-duration="30" data-track-index="11" data-volume="0.14"></audio>
      <audio id="el-bgm2" src="assets/bgm/track.wav" data-start="30" data-duration="{min(30, total - 30):.1f}" data-track-index="12" data-volume="0.14"></audio>
      <audio id="el-sfx1" src="assets/sfx/click-soft.mp3" data-start="4.6" data-duration="0.37" data-track-index="20" data-volume="0.3"></audio>
      <audio id="el-sfx2" src="assets/sfx/click-soft.mp3" data-start="18.6" data-duration="0.37" data-track-index="21" data-volume="0.3"></audio>
      <audio id="el-sfx3" src="assets/sfx/click-soft.mp3" data-start="28.6" data-duration="0.37" data-track-index="20" data-volume="0.3"></audio>
      <audio id="el-sfx4" src="assets/sfx/chime.mp3" data-start="{total - 6.5:.1f}" data-duration="2.5" data-track-index="22" data-volume="0.3"></audio>
    </div>

    <script>
      window.__timelines = window.__timelines || {{}};
      var tl = gsap.timeline({{ paused: true }});
      window.__timelines["main"] = tl;
      function cut(sel, start, dur) {{
        tl.fromTo(sel, {{ opacity: 0 }}, {{ opacity: 1, duration: 0.22, ease: "power2.out" }}, start);
        tl.to(sel, {{ opacity: 0, duration: 0.28, ease: "power2.in" }}, start + dur - 0.28);
      }}
{chr(10).join(cuts)}
      tl.to({{}}, {{ duration: {total} }}, 0);
    </script>
  </body>
</html>
"""
(ROOT / "index.html").write_text(index, encoding="utf-8")
print("total", total)
