param(
    $ServerUrl = "http://10.10.10.44:8000",
    $TimeRangeHours = 2
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

function Get-JsonHash{
    param(
        $payload
    )
    if ($payload -isnot [string]) {
        $payload = $payload | ConvertTo-Json -Depth 10 -Compress
    }
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    return [System.BitConverter]::ToString($hash.ComputeHash($jsonBytes)) -replace '-',''
}


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


$event_logs = Get-WinLogs -TimeRangeHours $TimeRangeHours
$processes = Get-Processes
$network = Get-NetworkInfo
$registry = Get-Registry
$scheduled_tasks = Get-ScheduledTasks
$web_logs = Get-WebServerLogs #-FromDate (Get-Date).AddHours(-24)

$result = @{
    metadata = @{
        hostname = $Hostname
        collected_at = $CollectionTime
        os_version =(Get-CimInstance Win32_OperatingSystem).Caption
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
        event_logs = (Get-JsonHash $event_logs)
        processes = (Get-JsonHash $processes)
        network = (Get-JsonHash $network)
        registry = (Get-JsonHash $registry)
        scheduled_tasks = (Get-JsonHash $scheduled_tasks)
        web_logs = (Get-JsonHash $web_logs)
    }
}

$jsonPayload = $result | ConvertTo-Json -Depth 10

Write-Host "[*] Total JSON size: $([math]::Round($jsonPayload.Length / 1MB, 2)) MB"
$jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload) 
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashString = [System.BitConverter]::ToString($sha.ComputeHash($jsonBytes)) -replace '-', ''

Write-Host "[*] SHA256: $hashString"
Write-Host "[*] Bytes length: $($jsonBytes.Length)"
$hashString = Get-JsonHash $jsonPayload
Write-Host "[*] SHA256: $hashString"
Write-Host "[*] Bytes length: $($jsonBytes.Length)"

Write-Host "[*] Sending data to the probe..."

try{
    $client = New-Object System.Net.WebClient
    $client.Headers.Add("Content-Type", "application/json")
    $client.Headers.Add("X-Collection-Hash", $hashString)
    
    $responseBytes = $client.UploadData("$ServerUrl/collect", "POST", $jsonBytes)
    $response = [System.Text.Encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json
    
    Write-Host "[+] Data sent succesfully" -ForegroundColor Green
    Write-Host "[+] Server response: $($response.status)" -ForegroundColor Green
}catch{
    Write-Host "[-] Failed to send data: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[-] Server detail: $($_.ErrorDetails.Message)" -ForegroundColor Red
}

Write-Host "[*] Collection complete." -ForegroundColor Green

