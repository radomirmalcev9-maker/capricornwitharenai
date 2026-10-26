@echo off
rem Copies Capri into the GitHub repo folder (Desktop\capricorn by default),
rem skipping private files: settings, log, Arena session, reports, samples and the speech model.
set "SRC=%~dp0.."
set "DST=%USERPROFILE%\Desktop\capricorn"
if not "%~1"=="" set "DST=%~1"
robocopy "%SRC%" "%DST%" /E /XD models reports samples arena_state __pycache__ .git .claude /XF config.json capri.log *.pyc capri.zip /NFL /NDL /NJH /NP
echo.
echo Done. Now open GitHub Desktop: Commit to main, then Push origin.
pause
