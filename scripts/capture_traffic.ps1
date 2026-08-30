<#
.SYNOPSIS
    Captures a diverse traffic session using tshark, deliberately
    triggering different TCP flag behaviors (SYN, FIN, RST, sustained
    ACK/PSH) instead of just recording passive background traffic.

.IMPORTANT
    Only run this on a machine/network you own or are authorized to
    monitor. The RST-generation step only probes 127.0.0.1 (your own
    machine) - do not repoint it at hosts you don't control.

.USAGE
    Run PowerShell AS ADMINISTRATOR (right-click PowerShell -> Run as Administrator),
    then:
        .\capture_traffic.ps1 -Duration 300 -OutFile tcpdump_session1.txt

    First time only - find your tshark interface number:
        & "C:\Program Files\Wireshark\tshark.exe" -D
    Then pass it:
        .\capture_traffic.ps1 -Duration 300 -InterfaceNumber 3 -OutFile session1.txt
#>

param(
    [int]$Duration = 300,
    [int]$InterfaceNumber = 1,
    [string]$OutFile = "tcpdump_session_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [string]$TsharkPath = "C:\Program Files\Wireshark\tshark.exe"
)

if (-not (Test-Path $TsharkPath)) {
    Write-Host "tshark.exe not found at '$TsharkPath'." -ForegroundColor Red
    Write-Host "Locate it (usually inside your Wireshark install folder) and pass -TsharkPath, e.g.:"
    Write-Host '  .\capture_traffic.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe"'
    exit 1
}

Write-Host "=== Traffic capture starting ===" -ForegroundColor Cyan
Write-Host "Duration:   ${Duration}s"
Write-Host "Interface#: $InterfaceNumber  (run 'tshark -D' to list/confirm)"
Write-Host "Output:     $OutFile"
Write-Host "================================="

# Start tshark in the background, writing default summary lines
# (same format your parser.py already expects: time, IPs, ports, flags, Len=)
$tsharkArgs = @("-i", $InterfaceNumber, "-n", "-l", "tcp or udp")
$tsharkProc = Start-Process -FilePath $TsharkPath -ArgumentList $tsharkArgs `
    -RedirectStandardOutput $OutFile -NoNewWindow -PassThru

Write-Host "tshark running (PID $($tsharkProc.Id)). Generating varied traffic..."
Start-Sleep -Seconds 2

$sites = @("google.com","github.com","wikipedia.org","cloudflare.com","amazon.com",
           "microsoft.com","apple.com","netflix.com","reddit.com","stackoverflow.com")

# --- 1. SYN-heavy: open many new connections in quick succession ---
Write-Host "[1/5] Generating SYN traffic (new connections)..." -ForegroundColor Yellow
foreach ($site in $sites) {
    Start-Job -ScriptBlock { param($s) curl.exe -s -o NUL --max-time 1 "https://$s" } -ArgumentList $site | Out-Null
}
Get-Job | Wait-Job | Out-Null
Get-Job | Remove-Job
Start-Sleep -Seconds 2

# --- 2. FIN-heavy: open-then-quickly-close connections ---
Write-Host "[2/5] Generating FIN traffic (quick connection close)..." -ForegroundColor Yellow
foreach ($site in $sites) {
    Start-Job -ScriptBlock { param($s) curl.exe -s -o NUL --max-time 1 "https://$s" } -ArgumentList $site | Out-Null
}
Get-Job | Wait-Job | Out-Null
Get-Job | Remove-Job
Start-Sleep -Seconds 2

# --- 3. RST traffic: connect to a closed local port on purpose ---
#     Only probes localhost - safe, doesn't touch external hosts.
Write-Host "[3/5] Generating RST traffic (closed local port)..." -ForegroundColor Yellow
foreach ($port in 9991..9995) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connectTask = $client.ConnectAsync("127.0.0.1", $port)
        $connectTask.Wait(500) | Out-Null
        $client.Close()
    } catch {}
}
Start-Sleep -Seconds 2

# --- 4. Sustained ACK/PSH-ACK: larger data transfer ---
Write-Host "[4/5] Generating sustained ACK/PSH-ACK traffic (larger download)..." -ForegroundColor Yellow
curl.exe -s -o NUL --max-time 15 "https://speed.hetzner.de/100MB.bin"
Start-Sleep -Seconds 2

# --- 5. Idle period: natural background traffic ---
Write-Host "[5/5] Idle period for natural background traffic..." -ForegroundColor Yellow
$remaining = $Duration - 30
if ($remaining -gt 0) {
    Start-Sleep -Seconds $remaining
}

Write-Host "Stopping capture..." -ForegroundColor Cyan
Stop-Process -Id $tsharkProc.Id -Force -ErrorAction SilentlyContinue

$lineCount = (Get-Content $OutFile | Measure-Object -Line).Lines
Write-Host "=================================" -ForegroundColor Green
Write-Host "Capture complete: $OutFile"
Write-Host "Lines captured: $lineCount"
Write-Host "=================================" -ForegroundColor Green
Write-Host "Run this multiple times across different sessions/days for more"
Write-Host "variety, then combine the files before running parser.py:"
Write-Host '  Get-Content tcpdump_session*.txt | Set-Content tcpdump_combined.txt'
