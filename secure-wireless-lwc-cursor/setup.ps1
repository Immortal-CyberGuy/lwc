# One-shot setup: venv, pip install, verify_setup, pytest (Windows PowerShell)
# Run from project root:  .\setup.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$py = Join-Path $root "venv\Scripts\python.exe"
$pip = Join-Path $root "venv\Scripts\pip.exe"

if (-not (Test-Path $py)) {
    Write-Host "Creating venv..."
    python -m venv venv
}

Write-Host "Installing dependencies..."
& $pip install -r (Join-Path $root "requirements.txt")

Write-Host "verify_setup.py..."
& $py (Join-Path $root "verify_setup.py")

Write-Host "pytest..."
& $py -m pytest (Join-Path $root "tests") -q --tb=no

Write-Host ""
Write-Host "Done. Always use this interpreter for CLI:"
Write-Host "  .\venv\Scripts\python.exe main.py serve ..."
Write-Host "Or:  .\venv\Scripts\Activate.ps1   then   python main.py ..."
