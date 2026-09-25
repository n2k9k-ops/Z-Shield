@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   Z-Shield - envoi de la mise a jour
echo ============================================
echo.
git add -A
git commit -m "Z-Shield update"
if errorlevel 1 echo (Rien a committer, ou commit deja fait - on tente le push quand meme)
echo.
git push
echo.
echo ============================================
echo   Termine. Render va redeployer tout seul.
echo   (Regarde l'onglet Events de ton service Render)
echo ============================================
pause
