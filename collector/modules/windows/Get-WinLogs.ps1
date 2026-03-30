function Convert-EventToDict {
    param($event)
    $xml = [xml]$event.ToXml()
    $eventData = @{}
    $xml.Event.EventData.Data | ForEach-Object {
        if ($_.Name) {
            $eventData[$_.Name] = $_.'#text'
        }
    }
    return @{
        time_created = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        event_id     = $event.Id
        message      = $event.Message
        event_data   = $eventData
    }
}



function Get-WinLogs{
    param(
        [int]$TimeRangeHours = 48
    )

    $StartTime = (Get-Date).AddHours(-$TimeRangeHours)
    Write-Host "[*] Collecting event logs from last $TimeRangeHours hours..."

    $winlogs_result = @{
        wmi = @()
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


    # --- WMI ---
    try {
        $wmiEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WMI-Activity/Operational'
            StartTime = $StartTime
        } -ErrorAction Stop

        $winlogs_result.wmi = $wmiEvents | ForEach-Object {
            @{
                time_created = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_id     = $_.Id
                message      = $_.Message
            }
        }       
         Write-Host "[+] WMI Activity: $($winlogs_result.wmi.Count) events"
    }
    catch {
        Write-Host "[-] WMI Activity not available: $($_.Exception.Message)" -ForegroundColor Yellow
        $winlogs_result.warnings += "WMI Activity not available: $($_.Exception.Message)"
    }

    # ---- Security events -----
    $securityIds = @(4624, 4625, 4688, 4698, 4702, 4720, 4732)
    try{
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $securityIds
            StartTime = $StartTime
        } -ErrorAction Stop

        $winlogs_result.security = $securityEvents | ForEach-Object {Convert-EventToDict $_}
        
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

        $winlogs_result.sysmon = $sysmonEvents | ForEach-Object {Convert-EventToDict $_}
        
        $winlogs_result.log_metadata.oldest_sysmon_event = 
            $sysmonEvents | Select-Object -Last 1 | 
            Select-Object -ExpandProperty TimeCreated | 
            ForEach-Object { $_.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
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

        $winlogs_result.powershell = $psEvents | ForEach-Object {Convert-EventToDict $_}
        
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
                Level = @(2,3)
                StartTime = $StartTime
            } -ErrorAction Stop

            $winlogs_result[$logName.ToLower()] = $events | ForEach-Object {Convert-EventToDict $_}
            
            Write-Host "[+] $logName`: $($winlogs_result[$logName.ToLower()].Count) events"
        }
        catch {
            Write-Host "[-] $logName events: $($_.Exception.Message)" -ForegroundColor Red
            $winlogs_result.warnings += "$logName collection failed: $($_.Exception.Message)"
        }
    }
    return $winlogs_result
}

