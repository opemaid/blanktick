@echo off
rem Starts Blanktick's MCP server for Claude Code.
rem
rem Standard output IS the protocol, so this script must print nothing to it:
rem every message below goes to stderr (1>&2), and the server is the last
rem thing run so its stdin/stdout are the ones Claude Code is talking to.
rem
rem Where Blanktick lives depends on how it was installed, so look in order:
rem   1. BLANKTICK_EXE, if you set it (portable zip, source build, anywhere)
rem   2. the per-user MSI location
rem   3. a machine-wide install
setlocal

if defined BLANKTICK_EXE if exist "%BLANKTICK_EXE%" goto run

for %%P in (
  "%LOCALAPPDATA%\Blanktick\Blanktick.exe"
  "%LOCALAPPDATA%\Programs\Blanktick\Blanktick.exe"
  "%ProgramFiles%\Blanktick\Blanktick.exe"
) do if exist %%P (
  set "BLANKTICK_EXE=%%~P"
  goto run
)

echo Blanktick.exe was not found. Install Blanktick from https://blanktick.org, 1>&2
echo or set BLANKTICK_EXE to the full path of Blanktick.exe. 1>&2
exit /b 1

:run
"%BLANKTICK_EXE%" --mcp
