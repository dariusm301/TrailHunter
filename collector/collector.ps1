param(
    $ServerUrl = "http://172.28.112.1:8000",
    $TimeRangeHours = 48,
    $Token = $null
)
$Hostname = $env:COMPUTERNAME
$CollectionTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$modules = @(
    "windows/Get-WinLogs.ps1"
    "windows/Get-Processes.ps1"
    "windows/Get-NetworkInfo.ps1"
    "windows/Get-Registry.ps1"
    "windows/Get-ScheduledTasks.ps1"
    "windows/Get-WebServerLogs.ps1"
)

function Get-JsonHash {
    param($payload)
    if ($payload -isnot [string]) {
        $payload = $payload | ConvertTo-Json -Depth 10 -Compress
    }
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    return [System.BitConverter]::ToString($hash.ComputeHash($jsonBytes)) -replace '-',''
}

function Write-ServerError {
    param($ErrorRecord)
    Write-Host "[-] Failed: $($ErrorRecord.Exception.Message)" -ForegroundColor Red
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        Write-Host "[-] Server detail: $($ErrorRecord.ErrorDetails.Message)" -ForegroundColor Red
    }
    elseif ($ErrorRecord.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($ErrorRecord.Exception.Response.GetResponseStream())
            Write-Host "[-] Server detail: $($reader.ReadToEnd())" -ForegroundColor Red
        } catch {}
    }
}

$headers = @{}
if ($Token) {
    $headers["X-Probe-Token"] = $Token
}

foreach ($module in $modules) {
    try {
        $url = "$ServerUrl/$module"
        $scriptContent = Invoke-RestMethod -Uri $url -Headers $headers
        Invoke-Expression $scriptContent
        Write-Host "[+] Loaded: $module" -ForegroundColor Green
    }
    catch {
        Write-ServerError $_
    }
}

$event_logs       = Get-WinLogs -TimeRangeHours $TimeRangeHours
$processes        = Get-Processes
$network          = Get-NetworkInfo
$registry         = Get-Registry
$scheduled_tasks  = Get-ScheduledTasks
$web_logs         = Get-WebServerLogs

$result = @{
    metadata = @{
        hostname     = $Hostname
        collected_at = $CollectionTime
        os_version   = (Get-CimInstance Win32_OperatingSystem).Caption
    }
    modules = @{
        event_logs      = $event_logs
        processes       = $processes
        network         = $network
        registry        = $registry
        scheduled_tasks = $scheduled_tasks
        web_logs        = $web_logs
    }
    module_hashes = @{
        event_logs      = (Get-JsonHash $event_logs)
        processes       = (Get-JsonHash $processes)
        network         = (Get-JsonHash $network)
        registry        = (Get-JsonHash $registry)
        scheduled_tasks = (Get-JsonHash $scheduled_tasks)
        web_logs        = (Get-JsonHash $web_logs)
    }
}

$jsonPayload = $result | ConvertTo-Json -Depth 10
$jsonBytes   = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
$hashString  = Get-JsonHash $jsonPayload

Write-Host "[*] Total JSON size: $([math]::Round($jsonBytes.Length / 1MB, 2)) MB"
Write-Host "[*] SHA256: $hashString"
Write-Host "[*] Sending data to the probe..."

$ingestHeaders = $headers.Clone()
$ingestHeaders["X-Collection-Hash"] = $hashString

try {
    $response = Invoke-RestMethod -Uri "$ServerUrl/api/probe/ingest" `
        -Method Post `
        -Headers $ingestHeaders `
        -ContentType "application/json" `
        -Body $jsonBytes

    Write-Host "[+] Data sent succesfully" -ForegroundColor Green
    Write-Host "[+] Server response: $($response.status)" -ForegroundColor Green
    Write-Host "[*] Collection complete." -ForegroundColor Green
}
catch {
    Write-ServerError $_
}
