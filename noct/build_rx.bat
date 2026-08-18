@echo off
REM Build every binary that must agree on the proof of work against real
REM RandomX. A node, pool, and miner built with different PoW cannot work
REM together (the miner's shares are simply never valid), so they are built here
REM together rather than one at a time.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
echo === cargo test (noct-randomx, release) ===
cd /d C:\Users\MINE\OneDrive\Desktop\Coin1\noct\randomx
cargo test --release
if errorlevel 1 exit /b 1
echo === cargo build noctd + noct-miner --features randomx (release) ===
cd /d C:\Users\MINE\OneDrive\Desktop\Coin1\noct
cargo build --release -p noct-node --features randomx
if errorlevel 1 exit /b 1
echo === cargo build noct-poold --features randomx (release) ===
cargo build --release -p noct-pool --features randomx
if errorlevel 1 exit /b 1
echo === done: noctd, noct-miner and noct-poold all built on RandomX ===
