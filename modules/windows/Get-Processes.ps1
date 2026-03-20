function Get-Processes{
    Write-Host "[*] Collecting process list..."

    $processes_result = @{
        processes = @()
        warnings = @()
        collection_time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    try{
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop

        $processes_result.processes = $processes | ForEach-Object {
            $hash = "no_path"
            if ($_.ExecutablePath -and (Test-Path $_.ExecutablePath)){
                try{
                    $hash = (Get-FileHash -Path $_.ExecutablePath -Algorithm SHA256).Hash
                }
                catch{
                    $hash = "access_denied"
                }
            }
            $owner = $null
            try{
                $ownerInfo = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
               $owner = if ($ownerInfo.User) {
                            "$($ownerInfo.Domain)\$($ownerInfo.User)"
                        } else {
                            "system"
                        }
            }
            catch{
                $owner = "unknown"
            }

            $startTime = if ($_.CreationDate) {                                                 
                $_.CreationDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }else {
                "unknown"
            }


            @{
                name = $_.Name
                pid = $_.ProcessId
                parent_pid = $_.ParentProcessId
                executable_path = $_.ExecutablePath
                command_line = $_.CommandLine
                owner = $owner
                hash_sha256 = $hash
                start_time = $startTime
            }
        }
        Write-Host "[+] Processes: $($processes_result.processes.Count) found"
        
    }
    catch{
        Write-Host "[-] Error when trying to get process list... $($_.Exception.Message)" -ForegroundColor Red
        $processes_result.warnings += "Processes collection failed: $($_.Exception.Message)"
    }
    return $processes_result
}