#!/usr/bin/env pwsh
# start.ps1 — launches both the FastAPI backend and Vite frontend
# Usage: .\start.ps1

$root = $PSScriptRoot

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   Security Investigator — Standalone  ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "  ✅ Python:  $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Python not found. Please install Python 3.11+" -ForegroundColor Red; exit 1
}

# 2. Check Node
try {
    $nodeVersion = node --version 2>&1
    Write-Host "  ✅ Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Node.js not found. Please install Node.js 18+" -ForegroundColor Red; exit 1
}

# 3. Check config
if (-not (Test-Path "$root\config.json")) {
    Write-Host ""
    Write-Host "  ⚠️  config.json not found!" -ForegroundColor Yellow
    Write-Host "     Copy config.json.template to config.json and fill in your values." -ForegroundColor Yellow
    Write-Host ""
}

# 4. Install backend deps if needed
Write-Host ""
Write-Host "  Installing backend dependencies..." -ForegroundColor Cyan
pip install -q -r "$root\backend\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠️  Some backend dependencies may not have installed correctly." -ForegroundColor Yellow
}

# 5. Install frontend deps if needed
if (-not (Test-Path "$root\frontend\node_modules")) {
    Write-Host "  Installing frontend dependencies..." -ForegroundColor Cyan
    Push-Location "$root\frontend"; npm install --silent; Pop-Location
}

Write-Host ""
Write-Host "  Starting services:" -ForegroundColor Cyan
Write-Host "    🐍 Backend  → http://localhost:8000  (API + Swagger)" -ForegroundColor White
Write-Host "    ⚡ Frontend → http://localhost:5173  (Dashboard)" -ForegroundColor White
Write-Host ""
Write-Host "  Press Ctrl+C twice to stop both services." -ForegroundColor DarkGray
Write-Host ""

# 6. Launch both in background jobs
$backend = Start-Job -ScriptBlock {
    Set-Location $using:root
    python -m backend.main
}

$frontend = Start-Job -ScriptBlock {
    Set-Location "$using:root\frontend"
    npm run dev
}

# 7. Open browser after a short delay
Start-Sleep -Seconds 3
Start-Process "http://localhost:5173"

# 8. Stream output from both jobs
try {
    while ($true) {
        Receive-Job $backend   | ForEach-Object { Write-Host "  [API] $_" -ForegroundColor DarkCyan }
        Receive-Job $frontend  | ForEach-Object { Write-Host "  [FE]  $_" -ForegroundColor DarkGreen }
        Start-Sleep -Milliseconds 500

        if ($backend.State -eq 'Failed') {
            Write-Host "  ❌ Backend job failed!" -ForegroundColor Red
            Receive-Job $backend -ErrorAction SilentlyContinue | Write-Host
            break
        }
    }
} finally {
    Stop-Job $backend, $frontend -ErrorAction SilentlyContinue
    Remove-Job $backend, $frontend -ErrorAction SilentlyContinue
    Write-Host "`n  Stopped." -ForegroundColor DarkGray
}
