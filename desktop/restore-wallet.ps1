# Restore the Noct desktop wallet to the founder key.
#
# WHY THIS EXISTS
# ---------------
# Claude Code runs inside the Claude desktop app's MSIX container, which
# redirects ALL of %APPDATA% (Local, LocalLow, Roaming) into
#   %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\
# So every wallet file written while assisting -- the key, the address pin, the
# block chain -- landed in the container, not in the real %APPDATA%. The wallet
# app, launched normally from the Start Menu, reads the REAL %APPDATA%, found it
# empty, and did the one thing that looks like catastrophe: it created a brand
# new, empty wallet and showed its zero balance.
#
# The coins were never lost. They belong to the founder key, which is sitting in
# the container copy. This script puts it back where the app will actually read
# it.
#
# RUN THIS IN YOUR OWN POWERSHELL WINDOW -- not through Claude, or it will be
# redirected right back into the container.
#
#   powershell -ExecutionPolicy Bypass -File "<path to this file>"

$ErrorActionPreference = 'Stop'

$FOUNDER = 'C4do37CzzKCV3XJHDinLAoL7MaEtRU5oHgGTWLVb8JBY5zEDayjqYqHG'
$src     = Join-Path $env:LOCALAPPDATA 'Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\noct-wallet-desktop'
$dst     = Join-Path $env:APPDATA 'noct-wallet-desktop'
$altPin  = Join-Path $env:LOCALAPPDATA 'Noct'
$cli     = Join-Path $PSScriptRoot '..\noct\target\release\noct-cli.exe'
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Host ''
Write-Host 'Noct wallet restore' -ForegroundColor Cyan
Write-Host ('  source (container): ' + $src)
Write-Host ('  target (real)     : ' + $dst)
Write-Host ''

# --- 1. the source must exist and must be the founder wallet -----------------
if (-not (Test-Path (Join-Path $src 'wallet.key'))) {
    throw "No wallet.key at $src -- nothing to restore from."
}
if (-not (Test-Path $cli)) {
    throw "noct-cli.exe not found at $cli -- build it first: cargo build --release"
}

$addr = (& $cli address --wallet (Join-Path $src 'wallet.key')).Trim()
if ($addr -notlike "$FOUNDER*") {
    throw "Refusing to continue: the source key derives $addr, not the founder wallet."
}
Write-Host ('  verified source key -> ' + $addr.Substring(0, 24) + '...') -ForegroundColor Green

# --- 2. stop anything holding the wallet ------------------------------------
Get-Process 'Noct Wallet', 'noctd', 'noct-walletd' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host ('  stopping ' + $_.Name + ' (pid ' + $_.Id + ')'); Stop-Process -Id $_.Id -Force }
Start-Sleep -Seconds 2

# --- 3. move the wrong wallet aside (never delete) ---------------------------
if (Test-Path $dst) {
    $aside = "$dst.replaced-$stamp"
    Move-Item $dst $aside
    Write-Host ('  moved the empty wallet aside -> ' + $aside) -ForegroundColor Yellow
}
if (Test-Path (Join-Path $altPin 'wallet.address')) {
    Move-Item (Join-Path $altPin 'wallet.address') (Join-Path $altPin "wallet.address.replaced-$stamp")
}

# --- 4. copy key, pin and chain into the real location ----------------------
New-Item -ItemType Directory -Force -Path $dst    | Out-Null
New-Item -ItemType Directory -Force -Path $altPin | Out-Null

foreach ($f in 'wallet.key', 'wallet.address', 'wallet.key.cache') {
    $p = Join-Path $src $f
    if (Test-Path $p) { Copy-Item $p $dst; Write-Host ('  copied ' + $f) }
}
if (Test-Path (Join-Path $src 'node')) {
    Copy-Item (Join-Path $src 'node') $dst -Recurse
    $blocks = Join-Path $dst 'node\blocks.dat'
    if (Test-Path $blocks) {
        Write-Host ('  copied chain (' + (Get-Item $blocks).Length + ' bytes of blocks)')
    }
}
Copy-Item (Join-Path $dst 'wallet.address') $altPin -ErrorAction SilentlyContinue

# --- 5. report ---------------------------------------------------------------
$final = (& $cli address --wallet (Join-Path $dst 'wallet.key')).Trim()
Write-Host ''
if ($final -like "$FOUNDER*") {
    Write-Host 'Restored. The wallet app will now open:' -ForegroundColor Green
    Write-Host ('  ' + $final)
    Write-Host ''
    Write-Host 'Next: install the current build, then start Noct Wallet.'
    Write-Host ('  "' + (Join-Path $PSScriptRoot 'dist\Noct Wallet Setup 0.1.0.exe') + '"')
} else {
    Write-Host ('UNEXPECTED: restored key derives ' + $final) -ForegroundColor Red
}
Write-Host ''
