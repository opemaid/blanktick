"""Emits compositions/frames/s1..s8.html and index.html for the
"How Claude connects to Blanktick" explainer.

Every on-screen fact is taken from docs/mcp.md, McpServer.kt, AssistantScreen.kt
or the real session in capture/ — nothing on screen is invented output.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).parent
FRAMES = ROOT / "compositions" / "frames"
FRAMES.mkdir(parents=True, exist_ok=True)

# (scene id, duration, voice duration) — durations padded around the VO.
SCENES = [
    ("s1", 6.2), ("s2", 9.6), ("s3", 5.4), ("s4", 6.0),
    ("s5", 8.0), ("s6", 10.4), ("s7", 8.4), ("s8", 4.6),
]
VOICE = {"01": 5.27, "02": 8.79, "03": 1.96, "04": 4.37,
         "05": 7.17, "06": 9.17, "07": 7.55, "08": 2.69}

TICK = '<svg viewBox="0 0 120 120"><path d="M 26 62 L 52 90 L 96 34"/></svg>'

BASE_CSS = """
@font-face{font-family:"bt-ui";src:local("Segoe UI"),local("SegoeUI");font-weight:400}
@font-face{font-family:"bt-ui";src:local("Segoe UI Semibold"),local("SegoeUI-Semibold");font-weight:600}
@font-face{font-family:"bt-mono";src:local("Cascadia Mono"),local("Consolas")}
@font-face{font-family:"bt-ui";src:local("Segoe UI Bold"),local("SegoeUI-Bold");font-weight:700}
#root{position:relative;width:1920px;height:1080px;overflow:hidden;background:#FAF9F6;container-type:size;font-family:"bt-ui","Segoe UI",sans-serif;color:#0B0D0C}
.wrap{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;padding:4cqw 9cqw}
.eyebrow{font-size:.95cqw;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#0F4D3F;margin-bottom:1cqw;opacity:0}
.h1{font-size:4.2cqw;font-weight:700;letter-spacing:-.02em;line-height:1.08;opacity:0}
.h2{font-size:2.6cqw;font-weight:700;letter-spacing:-.02em;line-height:1.12;opacity:0}
.k{color:#0F4D3F}
.c{color:#C2613F}
.sub{font-size:1.45cqw;color:#5A6260;line-height:1.5;margin-top:1.4cqw;opacity:0}
.card{background:rgba(15,77,63,.04);border:1.5px solid rgba(15,77,63,.2);border-radius:14px}
.pill{display:inline-flex;align-items:center;gap:.6cqw;padding:.55cqw 1.2cqw;border-radius:100px;background:rgba(15,77,63,.08);border:1.5px solid rgba(15,77,63,.2);color:#0F4D3F;font-weight:600;font-size:1.05cqw;opacity:0}
.mono{font-family:"bt-mono",monospace}
.term{background:#0B0D0C;color:#FAF9F6;border-radius:14px;padding:1.6cqw 2cqw}
.tick{width:1.4cqw;height:1.4cqw;flex:none}
.tick path{fill:none;stroke:#0F4D3F;stroke-width:16;stroke-linecap:round;stroke-linejoin:round}
.step{font-size:1cqw;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#FAF9F6;background:#0F4D3F;border-radius:100px;padding:.35cqw 1cqw;display:inline-block}
"""


def scene(sid, dur, css, body, js):
    return f"""<template>
  <div id="root" data-composition-id="{sid}" data-start="0" data-duration="{dur}" data-width="1920" data-height="1080">
    <style>{BASE_CSS}{css}</style>
    <div class="wrap clip" id="{sid}-wrap" data-start="0" data-duration="{dur}" data-track-index="0">
{body}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
    <script>
      (function(){{
        window.__timelines = window.__timelines || {{}};
        var tl = gsap.timeline({{ paused: true }});
        function up(sel, t, d){{ tl.fromTo(sel, {{opacity:0, y:16}}, {{opacity:1, y:0, duration:d||0.45, ease:"power2.out"}}, t); }}
        function pop(sel, t){{ tl.fromTo(sel, {{opacity:0, scale:0.92}}, {{opacity:1, scale:1, duration:0.35, ease:"back.out(2)"}}, t); }}
{js}
        tl.set({{}}, {{}}, {dur});
        window.__timelines["{sid}"] = tl;
      }})();
    </script>
  </div>
</template>
"""


def typed(text, cls="ch"):
    """One span per character so typing is seek-safe (opacity steps, no text mutation)."""
    out = []
    for ch in text:
        esc = {"<": "&lt;", ">": "&gt;", "&": "&amp;", " ": "&nbsp;"}.get(ch, ch)
        out.append(f'<span class="{cls}">{esc}</span>')
    return "".join(out)


S = {}

# ---- S1 title -------------------------------------------------------------
S["s1"] = scene("s1", 6.2, """
#logo{width:7cqw;height:7cqw;border-radius:50%;background:#0F4D3F;display:flex;align-items:center;justify-content:center;margin-bottom:2cqw;opacity:0}
#logo svg{width:4.2cqw;height:4.2cqw}
#logo path{fill:none;stroke:#FAF9F6;stroke-width:14;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:120;stroke-dashoffset:120}
""", f"""
      <div id="logo">{TICK}</div>
      <div class="eyebrow" id="e1">Blanktick &times; Claude</div>
      <div class="h1" id="t1">How <span class="c">Claude</span> connects<br>to <span class="k">Blanktick</span></div>
      <div class="sub" id="u1">Ask an AI how secure this PC is &mdash; and get answers read off the machine, not guesses.</div>
""", """
        pop("#logo", 0.1);
        tl.to("#logo path", {strokeDashoffset:0, duration:0.6, ease:"power2.out"}, 0.35);
        up("#e1", 0.7); up("#t1", 0.9, 0.6); up("#u1", 1.7);
""")

# ---- S2 how it works --------------------------------------------------------
S["s2"] = scene("s2", 9.6, """
#row{display:flex;align-items:center;justify-content:space-between;margin-top:2.6cqw}
.node{width:24cqw;padding:2cqw;opacity:0}
.node .nt{font-size:2.1cqw;font-weight:700}
.node .nd{font-size:1.1cqw;color:#5A6260;margin-top:.5cqw;line-height:1.45}
#pipe{width:30cqw;margin:0 2cqw;position:relative;height:9cqw;opacity:0}
.lane{position:absolute;left:0;right:0;height:3px;background:rgba(15,77,63,.25)}
#l1{top:2.6cqw}#l2{top:6.2cqw}
.lab{position:absolute;font-size:.9cqw;font-weight:600;color:#5A6260;left:50%;transform:translateX(-50%)}
#lb1{top:.6cqw}#lb2{top:7cqw}
.pkt{position:absolute;left:0;padding:.25cqw .7cqw;border-radius:6px;font-size:.85cqw;font-weight:600}
.pkt.req{top:1.8cqw;background:#C2613F;color:#FAF9F6}
.pkt.res{top:5.4cqw;background:#0F4D3F;color:#FAF9F6}
#chips{display:flex;gap:1.2cqw;margin-top:3cqw}
""", """
      <div class="eyebrow" id="e2">How it works</div>
      <div class="h2" id="t2">Blanktick is an <span class="k">MCP server</span>. Claude is the client.</div>
      <div id="row">
        <div class="node card" id="n1"><div class="nt c">Claude</div><div class="nd">Claude Desktop or Claude Code launches Blanktick as a child process</div></div>
        <div id="pipe">
          <div class="lane" id="l1"></div><div class="lane" id="l2"></div>
          <div class="lab mono" id="lb1">stdin &rarr; JSON-RPC request</div>
          <div class="lab mono" id="lb2">&larr; stdout reply</div>
          <div class="pkt req mono" id="p1">tools/call</div>
          <div class="pkt res mono" id="p2">result</div>
          <div class="pkt req mono" id="p3">tools/call</div>
          <div class="pkt res mono" id="p4">result</div>
        </div>
        <div class="node card" id="n2"><div class="nt k mono" style="font-size:1.7cqw">Blanktick.exe --mcp</div><div class="nd">Reads this machine, answers on stdout</div></div>
      </div>
      <div id="chips">
        <div class="pill" id="c1">stdio, not HTTP</div>
        <div class="pill" id="c2">No socket opened</div>
        <div class="pill" id="c3">Build fails on any networking API</div>
      </div>
""", """
        up("#e2", 0.1); up("#t2", 0.3, 0.55);
        pop("#n1", 1.2); pop("#n2", 1.6); tl.to("#pipe", {opacity:1, duration:0.4}, 1.9);
        [["#p1","#p2",2.3],["#p3","#p4",4.4]].forEach(function(p){
          tl.fromTo(p[0], {x:0, opacity:0}, {x:450, opacity:1, duration:1.3, ease:"power1.inOut"}, p[2]);
          tl.to(p[0], {opacity:0, duration:0.2}, p[2]+1.3);
          tl.fromTo(p[1], {x:480, opacity:0}, {x:0, opacity:1, duration:1.3, ease:"power1.inOut"}, p[2]+1.0);
          tl.to(p[1], {opacity:0, duration:0.2}, p[2]+2.3);
        });
        pop("#c1", 5.6); pop("#c2", 6.2); pop("#c3", 6.8);
""")

# ---- S3 Claude Code ---------------------------------------------------------
cmd = 'claude mcp add blanktick -- "C:\\Program Files\\Blanktick\\Blanktick.exe" --mcp'
S["s3"] = scene("s3", 5.4, """
#term{margin-top:2cqw;font-size:1.55cqw;line-height:1.5;opacity:0}
.prompt{color:#5FBFA3}
.ch{opacity:0}
#cur{display:inline-block;width:.75cqw;height:1.6cqw;background:#FAF9F6;vertical-align:middle}
#note{font-size:1.15cqw;color:#5A6260;margin-top:1.4cqw;opacity:0}
""", f"""
      <div><span class="step" id="st3" style="opacity:0">Step 1 &middot; Claude Code</span></div>
      <div class="h2" id="t3" style="margin-top:1cqw">One command.</div>
      <div class="term mono" id="term"><span class="prompt">&gt;&nbsp;</span>{typed(cmd)}<span id="cur"></span></div>
      <div id="note">Use the path to <span class="mono">Blanktick.exe</span> on your machine &mdash; the app&rsquo;s <b>Connect an assistant</b> screen shows yours.</div>
""", f"""
        up("#st3", 0.05); up("#t3", 0.2); up("#term", 0.45, 0.35);
        var chars = document.querySelectorAll("#s3-wrap .ch");
        for (var i = 0; i < chars.length; i++) tl.set(chars[i], {{opacity:1}}, 0.8 + i*0.032);
        tl.to("#cur", {{opacity:0, duration:0.01, repeat:5, yoyo:true, repeatDelay:0.25}}, 0.8 + {len(cmd)}*0.032);
        up("#note", 3.6);
""")

# ---- S4 Claude Desktop ------------------------------------------------------
json_lines = [
    '<span class="b">{</span>',
    '&nbsp;&nbsp;<span class="key">"mcpServers"</span>: <span class="b">{</span>',
    '&nbsp;&nbsp;&nbsp;&nbsp;<span class="key">"blanktick"</span>: <span class="b">{</span>',
    '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="key">"command"</span>: <span class="str">"C:\\\\Program Files\\\\Blanktick\\\\Blanktick.exe"</span>,',
    '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="key">"args"</span>: [<span class="str">"--mcp"</span>]',
    '&nbsp;&nbsp;&nbsp;&nbsp;<span class="b">}</span>',
    '&nbsp;&nbsp;<span class="b">}</span>',
    '<span class="b">}</span>',
]
S["s4"] = scene("s4", 6.0, """
#path{font-size:1.2cqw;color:#5A6260;margin-top:1cqw;opacity:0}
#code{margin-top:1.4cqw;font-size:1.45cqw;line-height:1.55;opacity:0}
.ln{opacity:0}
.key{color:#E9A27F}.str{color:#7FD3B8}.b{color:#CBD2CF}
#rs{margin-top:1.6cqw}
""", f"""
      <div><span class="step" id="st4" style="opacity:0">Step 2 &middot; Claude Desktop</span></div>
      <div class="h2" id="t4" style="margin-top:1cqw">Add one block, then restart Claude.</div>
      <div id="path" class="mono">%APPDATA%\\Claude\\claude_desktop_config.json</div>
      <div class="term mono" id="code">{''.join(f'<div class="ln">{l}</div>' for l in json_lines)}</div>
      <div id="rs"><span class="pill" id="p4">Cursor &amp; Windsurf take the same &ldquo;mcpServers&rdquo; block</span></div>
""", """
        up("#st4", 0.05); up("#t4", 0.2); up("#path", 0.5); up("#code", 0.7, 0.35);
        var ls = document.querySelectorAll("#s4-wrap .ln");
        for (var i = 0; i < ls.length; i++) tl.fromTo(ls[i], {opacity:0, x:-12}, {opacity:1, x:0, duration:0.25}, 1.0 + i*0.22);
        pop("#p4", 3.6);
""")

# ---- S5 the eight tools (names + descriptions from docs/mcp.md) -------------
tools = [
    ("blanktick_scan", "Full scan: score, every finding, what couldn&rsquo;t be checked"),
    ("blanktick_facts", "The raw readings &mdash; including the nulls"),
    ("blanktick_coverage", "What can and can&rsquo;t be checked here, and why"),
    ("blanktick_probe_script", "The exact PowerShell Blanktick runs"),
    ("blanktick_history", "Past scans: when, score, how many findings"),
    ("blanktick_search", "Findings across stored scans, by severity or rule"),
    ("blanktick_changes", "What&rsquo;s new and what&rsquo;s gone since last scan"),
    ("blanktick_netlog", "Review a Wireshark capture you exported"),
]
S["s5"] = scene("s5", 8.0, """
#grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1.2cqw;margin-top:2.2cqw}
.tool{padding:1.3cqw 1.4cqw;opacity:0}
.tn{font-size:1.12cqw;font-weight:700;color:#0F4D3F}
.td{font-size:1.02cqw;color:#5A6260;margin-top:.5cqw;line-height:1.4}
""", f"""
      <div class="eyebrow" id="e5">What Claude gets</div>
      <div class="h2" id="t5">Eight tools. <span class="k">All read-only.</span></div>
      <div id="grid">{''.join(f'<div class="tool card" id="tt{i}"><div class="tn mono">{n}</div><div class="td">{d}</div></div>' for i, (n, d) in enumerate(tools))}</div>
""", """
        up("#e5", 0.1); up("#t5", 0.3, 0.55);
        for (var i = 0; i < 8; i++) pop("#tt"+i, 1.0 + i*0.55);
""")

# ---- S6 a real exchange (history lines verbatim from capture/cov.jsonl) -----
S["s6"] = scene("s6", 10.4, """
.wrap{padding:3cqw 14cqw}
.msg{max-width:62cqw;padding:1.1cqw 1.5cqw;border-radius:14px;font-size:1.3cqw;line-height:1.45;opacity:0}
#q{align-self:flex-end;background:#0F4D3F;color:#FAF9F6}
#call{align-self:flex-start;margin-top:1.2cqw}
#out{margin-top:.9cqw;font-size:1cqw;line-height:1.6;padding:1.2cqw 1.6cqw;opacity:0;align-self:stretch}
#out .hd{color:#7FD3B8}
#a{align-self:flex-start;margin-top:1.2cqw;background:rgba(194,97,63,.07);border:1.5px solid rgba(194,97,63,.3)}
#a b{color:#0B0D0C}
.who{font-size:.85cqw;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#C2613F;margin-bottom:.3cqw}
#foot{font-size:.95cqw;color:#666D6B;margin-top:1.2cqw;opacity:0}
""", """
      <div class="msg" id="q">How has my security changed since last month?</div>
      <div id="call"><span class="pill mono" id="cp">&#9656; calling blanktick_history</span></div>
      <div class="term mono" id="out"><span class="hd">BLANKTICK SCAN HISTORY &mdash; a stored record, not a live reading</span><br>2026-10-28 (just now)&nbsp;&nbsp;score 67/100 FAIR&nbsp;&nbsp;10 finding(s), 57 run / 31 not checkable<br>2026-09-23 (34 d ago)&nbsp;&nbsp;score 81/100 GOOD&nbsp;&nbsp;&nbsp;5 finding(s), 38 run / 30 not checkable</div>
      <div class="msg" id="a"><div class="who">Claude</div>Your score went from <b>81 to 67</b> &mdash; but this scan ran <b>57 checks, not 38</b>, so more was looked at and more was found. <b>31 checks couldn&rsquo;t run</b> here: that&rsquo;s unknown, not a pass.</div>
      <div id="foot">Real output from this PC. Searchable history is off until you set <span class="mono">keepHistory=true</span>.</div>
""", """
        pop("#q", 0.2); pop("#cp", 1.4); up("#out", 2.2, 0.4);
        pop("#a", 4.4); up("#foot", 7.0);
""")

# ---- S7 every tool is a question -------------------------------------------
nots = ["fix a finding", "change a setting", "delete a file", "quarantine anything"]
S["s7"] = scene("s7", 8.4, """
#list{display:flex;gap:1.4cqw;margin-top:2.4cqw;flex-wrap:wrap}
.no{position:relative;font-size:1.6cqw;font-weight:600;color:#5A6260;padding:.8cqw 1.5cqw;opacity:0}
.no .strike{position:absolute;left:1cqw;right:1cqw;top:50%;height:3px;background:#B4451F;transform:scaleX(0);transform-origin:left}
#who{font-size:1.9cqw;font-weight:700;margin-top:2.6cqw;opacity:0}
#test{font-size:1.1cqw;color:#5A6260;margin-top:1cqw;opacity:0}
""", f"""
      <div class="eyebrow" id="e7">The promise</div>
      <div class="h1" id="t7">Every tool is a <span class="k">question</span>.</div>
      <div id="list">{''.join(f'<div class="no card" id="no{i}">{n}<div class="strike"></div></div>' for i, n in enumerate(nots))}</div>
      <div id="who"><span class="c">Claude</span> advises. <span class="k">You</span> decide and act.</div>
      <div id="test">A test fails the build if a tool is ever added whose name suggests otherwise.</div>
""", """
        up("#e7", 0.1); up("#t7", 0.3, 0.6);
        for (var i = 0; i < 4; i++) {
          pop("#no"+i, 1.6 + i*0.6);
          tl.to("#no"+i+" .strike", {scaleX:1, duration:0.3, ease:"power2.out"}, 1.9 + i*0.6);
        }
        up("#who", 4.9); up("#test", 5.9);
""")

# ---- S8 end card ------------------------------------------------------------
S["s8"] = scene("s8", 4.6, """
.wrap{align-items:center;text-align:center}
#logo8{width:8cqw;height:8cqw;border-radius:50%;background:#0F4D3F;display:flex;align-items:center;justify-content:center;opacity:0}
#logo8 svg{width:4.8cqw;height:4.8cqw}
#logo8 path{fill:none;stroke:#FAF9F6;stroke-width:14;stroke-linecap:round;stroke-linejoin:round}
#name{font-size:4.6cqw;font-weight:700;letter-spacing:-.02em;margin-top:1.6cqw;opacity:0}
#tag{font-size:1.5cqw;color:#5A6260;margin-top:.6cqw;opacity:0}
#url{font-size:1.6cqw;font-weight:700;color:#0F4D3F;margin-top:2cqw;opacity:0}
""", f"""
      <div id="logo8">{TICK}</div>
      <div id="name">Blanktick</div>
      <div id="tag">Free &middot; Offline &middot; Ready for <span class="c">Claude</span></div>
      <div id="url">blanktick.org</div>
""", """
        pop("#logo8", 0.1); up("#name", 0.4); up("#tag", 0.8); up("#url", 1.3);
""")

for sid, _ in SCENES:
    (FRAMES / f"{sid}.html").write_text(S[sid], encoding="utf-8")

# ---- index ------------------------------------------------------------------
t = 0.0
scene_divs, voice_tags, cuts, sfx = [], [], [], []
for i, (sid, dur) in enumerate(SCENES):
    n = f"{i + 1:02d}"
    scene_divs.append(f'      <div id="el-{sid}" class="scene" data-composition-id="{sid}" data-composition-src="compositions/frames/{sid}.html" data-start="{t:.1f}" data-duration="{dur}" data-track-index="{i % 2}"></div>')
    voice_tags.append(f'      <audio id="el-v{n}" src="assets/voice/{n}.wav" data-start="{t + 0.2:.1f}" data-duration="{VOICE[n]}" data-track-index="10" data-volume="1"></audio>')
    cuts.append(f'      cut("#el-{sid}", {t:.1f}, {dur});')
    sfx.append(f'      <audio id="el-sfx{n}" src="assets/sfx/click-soft.mp3" data-start="{t + 0.1:.1f}" data-duration="0.37" data-track-index="{20 + i % 2}" data-volume="0.3"></audio>')
    t += dur
total = round(t, 1)
sfx[-1] = f'      <audio id="el-sfx08" src="assets/sfx/chime.mp3" data-start="{total - 4.5:.1f}" data-duration="2.5" data-track-index="22" data-volume="0.3"></audio>'

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
{chr(10).join(scene_divs)}

{chr(10).join(voice_tags)}

      <audio id="el-bgm1" src="assets/bgm/track.wav" data-start="0" data-duration="30" data-track-index="11" data-volume="0.07"></audio>
      <audio id="el-bgm2" src="assets/bgm/track.wav" data-start="30" data-duration="{total - 30:.1f}" data-track-index="12" data-volume="0.07"></audio>

{chr(10).join(sfx)}
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
