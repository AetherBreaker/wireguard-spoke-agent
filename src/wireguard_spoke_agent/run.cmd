@echo off
rem Rendered by wireguard-spoke-agent from its package template; rewritten whenever the render differs.
set "AGENT_HOME={home}"
set "UV_PYTHON_INSTALL_DIR=%AGENT_HOME%\python"
set "UV_TOOL_DIR=%AGENT_HOME%\tools"
set "UV_TOOL_BIN_DIR=%AGENT_HOME%\bin"
set "UV_CACHE_DIR=%AGENT_HOME%\cache"
set "UV_MANAGED_PYTHON=1"
rem aeth-ext's fatal-exception handler (the Pushover alert) is a no-op unless Python runs optimised.
set "PYTHONOPTIMIZE=1"
rem Upgrade before the agent starts: Windows can't replace files of a running program. A failed upgrade never blocks the run.
"%AGENT_HOME%\uv\uv.exe" tool upgrade wireguard-spoke-agent{python_arg} >> "%AGENT_HOME%\logs\upgrade.log" 2>&1
rem One line: cmd parses it whole, so it never reads past it after the agent rewrites this file.
"%AGENT_HOME%\bin\wireguard-spoke-agent.exe" & exit /b
