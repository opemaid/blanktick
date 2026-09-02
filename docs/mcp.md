# Connecting a language model to Mume

Mume can act as an [MCP](https://modelcontextprotocol.io) server, so any model
that speaks MCP — Claude Desktop, Claude Code, Cursor, Windsurf, a local model
behind an MCP-capable client — can ask about this computer's security posture
and get real answers instead of guesses.

```
Mume.exe --mcp
```

## What it does not do

**Every tool is a question.** There is no tool that fixes a finding, changes a
setting, deletes a file or quarantines anything — not because it would be hard,
but because a model acting on a security report without a person in the loop is
a worse idea than any problem it would solve.

That is not a general principle borrowed from somewhere; it is the same promise
the app has made since its first commit. Mume reports, and the user decides and
acts. `McpServerTest` fails the build if a tool is ever added whose name
suggests otherwise.

It matters more here than it would elsewhere, because Mume ships a rule
(`DSK-AI-002`) telling people that an MCP entry lets a model run commands on
their machine and that it appears in none of the startup locations anything else
checks. Shipping an MCP server after writing that is only defensible if this one
is exactly what the app claims to be.

## It does not touch the network

MCP has two transports. The HTTP one would make Mume a network client and is not
implemented here at any level. This is **stdio**: your client launches Mume,
writes JSON-RPC to its standard input, and reads replies from its standard
output. No socket is opened, nothing is bound, nothing is connected to.

The desktop build's bytecode gate still forbids a networking API anywhere in
Mume's own classes, and it still passes with this in place.

## Tools

| Tool | What it answers |
|---|---|
| `mume_scan` | Full scan: score, every finding with its fix, and the checks that could not be performed. ~100 seconds. |
| `mume_facts` | The raw facts read off the machine, **including the nulls**. |
| `mume_probe_script` | The exact PowerShell Mume runs, so it can be read or re-run by hand. |
| `mume_coverage` | What Mume can and cannot check here, and why. Does not scan. |

`mume_facts` returning `null` for something means *the machine would not answer*,
not *no*. The server says so in its own instructions, because a model
summarising a scan is exactly the situation where "not checkable" gets rounded
to "fine".

## Setup

Claude Desktop — `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mume": {
      "command": "C:\\Program Files\\Mume\\Mume.exe",
      "args": ["--mcp"]
    }
  }
}
```

Claude Code:

```
claude mcp add mume -- "C:\Program Files\Mume\Mume.exe" --mcp
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
