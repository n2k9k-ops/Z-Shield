@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   Z-Shield - envoi de la mise a jour
echo ============================================
echo.
echo [1/2] Regeneration du paquet anticheat (.zip) depuis les sources...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-resources.ps1"
if errorlevel 1 (
  echo.
  echo ERREUR : la generation du zip a echoue. Push ANNULE.
  echo Verifie que les dossiers ..\zshield-ac et ..\zshield-agent existent.
  pause
  exit /b 1
)
echo.
echo [2/2] Commit et push...
git add -A
git commit -m "Z-Shield update"
if errorlevel 1 echo (Rien a committer, ou commit deja fait - on tente le push quand meme)
echo.
git push
echo.
echo ============================================
echo   Termine. Render va redeployer tout seul.
echo   Le .zip du panel est reconstruit a chaque push.
echo   (Regarde l'onglet Events de ton service Render)
echo ============================================
pause
