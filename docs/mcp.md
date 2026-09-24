# Connecting a language model to Blanktick

Blanktick can act as an [MCP](https://modelcontextprotocol.io) server, so any model
that speaks MCP — Claude Desktop, Claude Code, Cursor, Windsurf, a local model
behind an MCP-capable client — can ask about this computer's security posture
and get real answers instead of guesses.

```
Blanktick.exe --mcp
```

## What it does not do

**Every tool is a question.** There is no tool that fixes a finding, changes a
setting, deletes a file or quarantines anything — not because it would be hard,
but because a model acting on a security report without a person in the loop is
a worse idea than any problem it would solve.

That is not a general principle borrowed from somewhere; it is the same promise
the app has made since its first commit. Blanktick reports, and the user decides and
acts. `McpServerTest` fails the build if a tool is ever added whose name
suggests otherwise.

It matters more here than it would elsewhere, because Blanktick ships a rule
(`DSK-AI-002`) telling people that an MCP entry lets a model run commands on
their machine and that it appears in none of the startup locations anything else
checks. Shipping an MCP server after writing that is only defensible if this one
is exactly what the app claims to be.

## It does not touch the network

MCP has two transports. The HTTP one would make Blanktick a network client and is not
implemented here at any level. This is **stdio**: your client launches Blanktick,
writes JSON-RPC to its standard input, and reads replies from its standard
output. No socket is opened, nothing is bound, nothing is connected to.

The desktop build's bytecode gate still forbids a networking API anywhere in
Blanktick's own classes, and it still passes with this in place.

## Tools

| Tool | What it answers |
|---|---|
| `blanktick_scan` | Full scan: score, every finding with its fix, and the checks that could not be performed. ~100 seconds. |
| `blanktick_facts` | The raw facts read off the machine, **including the nulls**. |
| `blanktick_probe_script` | The exact PowerShell Blanktick runs, so it can be read or re-run by hand. |
| `blanktick_coverage` | What Blanktick can and cannot check here, and why. Does not scan. |
| `blanktick_history` | Past scans from the local store, newest first: when each ran, its score, how many findings. Reads the store, does not scan. |
| `blanktick_search` | Findings across stored scans, filtered by severity / rule / category / date. Reads the store, does not scan. |
| `blanktick_changes` | What is new and what is no longer found between the two most recent scans. Reads the store, does not scan. |
| `blanktick_netlog` | Review a Wireshark capture the user exported (CSV): domains queried, external destinations, cleartext protocols, and any queried name on the offline blocklist. Reads the file, captures nothing. |

The last three let a model **ask about the machine without re-running a
100-second scan** — it searches the stored record instead. They read; they never
scan and never write.

`blanktick_facts` returning `null` for something means *the machine would not answer*,
not *no*. The server says so in its own instructions, because a model
summarising a scan is exactly the situation where "not checkable" gets rounded
to "fine".

## The searchable history is off by default

`blanktick_history`, `blanktick_search` and `blanktick_changes` read a local
store of past scans. **It is empty until you turn it on**, because keeping a
record of how insecure a machine was is exactly what decision D-05 said not to
do — a file listing a machine's weaknesses is a map for whoever reads it next,
and *"the app never touches the network"* does not change that: a local file is
a local file.

So enabling it is your explicit choice. In `%APPDATA%\Blanktick\settings.conf`:

```
keepHistory=true
```

Then each completed scan appends one line to `%APPDATA%\Blanktick\history.jsonl`.
Two things keep it faithful to the reason D-05 existed:

- **Summary, not snapshot.** Only rule *outcomes* are stored — id, severity,
  category, the on-screen title, points. The specifics that would make it a
  target map (the actual DNS address, account names, open ports, full paths)
  live elsewhere and never reach this file. A test asserts the omission.
- **Every answer is dated.** A stored result is not a live reading, and the
  tools say so and print the age, so a model cannot read a day-old snapshot and
  report "you're fine".

Delete `history.jsonl` at any time, or set `keepHistory=false`, and recording
stops.

## Setup

Claude Desktop — `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blanktick": {
      "command": "C:\\Program Files\\Blanktick\\Blanktick.exe",
      "args": ["--mcp"]
    }
  }
}
```

Claude Code:

```
claude mcp add blanktick -- "C:\Program Files\Blanktick\Blanktick.exe" --mcp
```

Cursor / Windsurf use the same `mcpServers` shape in their own config files.

Running from a source checkout instead of an installed build:

```
gradlew :desktop:run --args="--mcp" --console=plain -q
```

That works, but Gradle prints to stdout in some configurations and **stdout is
the protocol** — a single stray line corrupts the stream and the client
disconnects with a parse error that names nothing useful. Prefer the packaged
executable for anything but debugging.

## A note on what the model will tell you

The score is deductions subtracted from 100, so it is only meaningful next to
the coverage. A machine where most checks could not run scores *high*, because
nothing was found to deduct for. The scan output states this every time, and the
server's instructions tell the model to carry it through — but it is worth
knowing when you read a cheerful summary.
