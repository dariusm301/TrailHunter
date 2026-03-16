function Get-WinLogs{
    param(
        [int]$TimeRangeHours = 48
    )

    $StartTime = (Get-Date).AddHours(-$TimeRangeHours)
    Write-Host "[*] Collecting event logs from last $TimeRangeHours hours..."

    $winlogs_result = @{
        security = @()
        sysmon = @()
        application = @()
        system = @()
        powershell = @()
        warnings = @()
        collection_time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") 
        log_metadata = @{
            oldest_security_event = $null
            oldest_sysmon_event   = $null
            audit_process_creation = (auditpol /get /subcategory:"Process Creation")
        }
    }    

    # Security events
    $securityIds = @(4688, 4624, 4625, 4698, 4702)
    try{
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $securityIds
            StartTime = $StartTime
        } -ErrorAction Stop

        $winlogs_result.security = $securityEvents | ForEach-Object {
            @{
                time_created = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_id = $_.Id
                message = $_.Message
            }
        }
        $winlogs_result.log_metadata.oldest_security_event = 
            $securityEvents | Select-Object -Last 1 | 
            Select-Object -ExpandProperty TimeCreated | 
            ForEach-Object { $_.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
        Write-Host "[+] Security: $($winlogs_result.security.Count) events found"
    }
    catch{
        Write-Host "[-]  Security events error: $($_.Exception.Message)" -ForegroundColor Red
        $winlogs_result.warnings += "Security collection failed: $($_.Exception.Message)"
    }

    # ----- Sysmon events ---------
    try{
        $sysmonEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            StartTime = $StartTime
        } -ErrorAction Stop

        $winlogs_result.sysmon = $sysmonEvents | ForEach-Object {
            @{
                time_created = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_id = $_.Id
                message = $_.Message
            }
        }
        $winlogs_result.log_metadata.oldest_sysmon_event = 
            $sysmonEvents | Select-Object -Last 1 | 
            Select-Object -ExpandProperty TimeCreated
        Write-Host "[+] Sysmon events: $($winlogs_result.sysmon.Count) found"

    }
    catch{
        Write-Host "[-] Sysmon not available: $($_.Exception.Message)" -ForegroundColor Red
        $winlogs_result.warnings += "Sysmon is not available: $($_.Exception.Message)"
    }


    try {
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = 4104
            StartTime = $StartTime
        } -ErrorAction Stop

        $winlogs_result.powershell = $psEvents | ForEach-Object {
            @{
                time_created = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_id     = $_.Id
                message      = $_.Message
            }
        }
        Write-Host "[+] PowerShell: $($winlogs_result.powershell.Count) events"
    }
    catch {
        Write-Host "[-] PowerShell log not available: $($_.Exception.Message)" -ForegroundColor Yellow
        $winlogs_result.warnings += "PowerShell log not available"
    }


    # ---- Application -----

     foreach ($logName in @('Application', 'System')) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $StartTime
            } -ErrorAction Stop

            $winlogs_result[$logName.ToLower()] = $events | ForEach-Object {
                @{
                    time_created = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    event_id     = $_.Id
                    level        = $_.LevelDisplayName
                    message      = $_.Message
                }
            }
            Write-Host "[+] $logName`: $($winlogs_result[$logName.ToLower()].Count) events"
        }
        catch {
            Write-Host "[-] $logName events: $($_.Exception.Message)" -ForegroundColor Red
            $winlogs_result.warnings += "$logName collection failed: $($_.Exception.Message)"
        }
    }
    return $winlogs_result
}
