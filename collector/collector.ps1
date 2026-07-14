    param(
        $ServerUrl = "http://172.16.0.1:8000",
        $TimeRangeHours = 48,
        $Token = $null
    )

    trap {
        Write-Host "`n[!] Unexpected error: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
        if ($Host.Name -eq "ConsoleHost") {
            Read-Host -Prompt "Press Enter to close"
        }
        exit 1
    }
    $CHUNK_SIZE = 10 * 1024 * 1024

    function Get-JsonHash {
        param($payload)
        if ($null -eq $payload) {
            $payload = "null"
        } elseif ($payload -isnot [string]) {
            $payload = $payload | ConvertTo-Json -Depth 10 -Compress
        }
        $hash = [System.Security.Cryptography.SHA256]::Create()
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        return [System.BitConverter]::ToString($hash.ComputeHash($jsonBytes)) -replace '-', ''
    }
    function Write-ServerError {
        param($ErrorRecord)
        Write-Host "[-] Failed: $($ErrorRecord.Exception.Message)" -ForegroundColor Red
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            Write-Host "[-] Server detail: $($ErrorRecord.ErrorDetails.Message)" -ForegroundColor Red
        } elseif ($ErrorRecord.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($ErrorRecord.Exception.Response.GetResponseStream())
                Write-Host "[-] Server detail: $($reader.ReadToEnd())" -ForegroundColor Red
            } catch {}
        }
    }

    function Exit-WithError {
        param($Message)
        Write-Host "[-] $Message" -ForegroundColor Red
        if ($Host.Name -eq "ConsoleHost") {
            Read-Host -Prompt "Press Enter to close"
        }
        exit 1
    }


    $headers = @{}
    if ($Token) { $headers["X-Probe-Token"] = $Token }


    $modules = @(
        "windows/Get-WinLogs.ps1"
        "windows/Get-Processes.ps1"
        "windows/Get-NetworkInfo.ps1"
        "windows/Get-Registry.ps1"
        "windows/Get-ScheduledTasks.ps1"
        "windows/Get-WebServerLogs.ps1"
    )

    foreach ($module in $modules) {
        try {
            $p = @{ Uri = "$ServerUrl/$module"; Headers = $headers }
            $scriptContent = Invoke-RestMethod @p
            Invoke-Expression $scriptContent
            Write-Host "[+] Loaded: $module" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to load: $module" -ForegroundColor Red
            Write-ServerError $_
        }
    }


    Write-Host "[*] Collecting data..." -ForegroundColor Cyan

    $event_logs      = Get-WinLogs -TimeRangeHours $TimeRangeHours
    $processes       = Get-Processes
    $network         = Get-NetworkInfo
    $registry        = Get-Registry
    $scheduled_tasks = Get-ScheduledTasks
    $web_logs        = Get-WebServerLogs

    $result = @{
        metadata = @{
            hostname     = $env:COMPUTERNAME
            collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
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
    $hashString  = Get-JsonHash $jsonBytes
    $totalChunks = [math]::Ceiling($jsonBytes.Length / $CHUNK_SIZE)

    Write-Host "[*] Total JSON size: $([math]::Round($jsonBytes.Length / 1MB, 2)) MB ($totalChunks chunks)"
    Write-Host "[*] SHA256: $hashString"

    Write-Host "[*] Starting upload session..." -ForegroundColor Cyan

    try {
        $p = @{ Uri = "$ServerUrl/api/probe/ingest/start"; Method = "Post"; Headers = $headers; TimeoutSec = 30 }
        $startResp = Invoke-RestMethod @p
        $uploadId = $startResp.upload_id
        Write-Host "[+] Upload session: $uploadId" -ForegroundColor Cyan
    } catch {
        Write-ServerError $_
        Exit-WithError "Failed to start upload session"
    }


    for ($i = 0; $i -lt $totalChunks; $i++) {
        $offset = $i * $CHUNK_SIZE
        $length = [math]::Min($CHUNK_SIZE, $jsonBytes.Length - $offset)
        $chunk  = New-Object byte[] $length
        [System.Array]::Copy($jsonBytes, $offset, $chunk, 0, $length)

        $chunkHeaders = $headers.Clone()
        $chunkHeaders["X-Chunk-Index"] = $i

        try {
            $p = @{
                Uri         = "$ServerUrl/api/probe/ingest/chunk/$uploadId"
                Method      = "Post"
                Headers     = $chunkHeaders
                ContentType = "application/octet-stream"
                Body        = $chunk
                TimeoutSec  = 60
            }
            Invoke-RestMethod @p | Out-Null
            Write-Host "[*] Chunk $($i + 1)/$totalChunks uploaded" -ForegroundColor Cyan
        } catch {
            Write-ServerError $_
            Exit-WithError "Failed on chunk $i - upload aborted"
        }
    }


    Write-Host "[*] Finalizing upload..." -ForegroundColor Cyan

    $ingestHeaders = $headers.Clone()
    $ingestHeaders["X-Collection-Hash"] = $hashString

    try {
        $p = @{ Uri = "$ServerUrl/api/probe/ingest/complete/$uploadId"; Method = "Post"; Headers = $ingestHeaders; TimeoutSec = 300 }
        $response = Invoke-RestMethod @p
        Write-Host "[+] Data sent successfully" -ForegroundColor Green
        Write-Host "[+] Server response: $($response.status)" -ForegroundColor Green
        if ($response.forwarded_to_analysis_server) {
            Write-Host "[+] Forwarded to analysis server" -ForegroundColor Green
        } else {
            Write-Host "[!] NOT forwarded to analysis server: $($response.forward_error)" -ForegroundColor Yellow
        }
    } catch {
        Write-ServerError $_
        Exit-WithError "Failed to complete upload"
    }

    Write-Host "[*] Collection complete." -ForegroundColor Green

    if ($Host.Name -eq "ConsoleHost") {
        Read-Host -Prompt "Press Enter to close"
    }
