$ServerUrl = "http://192.168.0.140:8000"
$TimeRangeHours = 48
$Hostname = $env:COMPUTERNAME
$CollectionTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$modules = @(
    "modules/windows/Get-WinLogs.ps1"
    "modules/windows/Get-Processes.ps1"
    "modules/windows/Get-NetworkInfo.ps1"
    "modules/windows/Get-Registry.ps1"
    "modules/windows/Get-ScheduledTasks.ps1"
    "modules/windows/Get-WebServerLogs.ps1"
)

foreach ($module in $modules) {
    try{
        $url = "$ServerUrl/$module"
        Invoke-Expression (New-Object Net.WebClient).DownloadString("$url")
        Write-Host "[+] Loaded: $module" -ForegroundColor Green
    }
    catch{
        Write-Host "[-] Failed to load $module : $($_.Exception.Message)" -Foreground Red
    }
}

$result = @{
    metadata = @{
        hostname = $Hostname
        collected_at = $CollectionTime
        os_version =(Get-CimInstance Win32_OperatingSystem).Caption
    }
    event_logs = Get-WinLogs -TimeRangeHours $TimeRangeHours
    processes = Get-Processes
    network = Get-NetworkInfo
    registry = Get-Registry
    scheduled_tasks = Get-ScheduledTasks
    web_logs = Get-WebServerLogs
}

$jsonPayload = $result | ConvertTo-Json -Depth 10

Write-Host "[*] Total JSON size: $([math]::Round($jsonPayload.Length / 1MB, 2)) MB"

Write-Host "[*] Collection complete." -ForegroundColor Green

