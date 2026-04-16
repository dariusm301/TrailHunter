function Get-WebServerLogs{
    param(
        [String]$Path = "C:\xampp\apache\logs",
        [array]$LogFiles = @(
            "access.log",
            "error.log"
        ),
        [DateTime]$FromDate = [DateTime]::MinValue
    )
    
    $weblog_result = @{
        data = @{}
        warnings = @()
    }

     function Parse-AccessLine {
        param([string]$Line)
        $pattern = '^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\S+) "([^"]*)" "([^"]*)"$'
        if ($Line -match $pattern) {
            return [ordered]@{
                client_ip   = $Matches[1]
                timestamp   = $Matches[2] 
                method      = $Matches[3]
                path        = $Matches[4]
                status_code = [int]$Matches[5]
                bytes       = if ($Matches[6] -eq '-') { $null } else { [int]$Matches[6] }
                referer     = $Matches[7]
                user_agent  = $Matches[8]
            }
        }
        return $null
    }

    function Parse-ErrorLine {
        param([string]$Line)
        $pattern = '^\[(\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\] \[([^\]]+)\] \[([^\]]+)\] (?:\[client ([^\]]+)\] )?(.+)$'
        if ($Line -match $pattern) {
            return [ordered]@{
                timestamp  = $Matches[1]
                level      = $Matches[2]   
                module     = $Matches[3]
                client     = if ($Matches[4]) { $Matches[4] } else { $null }
                message    = $Matches[5]
            }
        }
        return $null
    }


    function Get-LineDateApache{
        param(
            [String]$Line,
            [String]$LogType
        )
        
        # access.log: [10/Mar/2025:14:32:01 +0200]
        $accessDateRegex = '\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
        $accessDateFormat = 'dd/MMM/yyyy:HH:mm:ss'

        # error.log: [Mon Mar 10 14:32:01.123456 2025]
        $errorDateRegex  = '\[\w{3} (\w{3} \d{1,2} \d{2}:\d{2}:\d{2})\.\d+ (\d{4})\]'
        $errorDateFormat = 'MMM d HH:mm:ss yyyy'
        try{
            if ($LogType -eq "access"){
                if ($Line -match $accessDateRegex) {
                    return [DateTime]::ParseExact(
                        $Matches[1],
                        $accessDateFormat,
                        [System.Globalization.CultureInfo]::InvariantCulture
                    )
                }
            }
            elseif ($LogType -eq "error"){
                if ($Line -match $errorDateRegex) {
                    $datePart = "$($Matches[1]) $($Matches[2])"
                    return [DateTime]::ParseExact(
                        $datePart,
                        $errorDateFormat,
                        [System.Globalization.CultureInfo]::InvariantCulture
                    )
                }
            }
        }
        catch{

        }
        return $null
    }

    try{
        Write-Host "[*] Collecting web server logs..."

        $filterActive = $FromDate -ne [DateTime]::MinValue

        foreach ($LogFile in $LogFiles){
            $fullPath = Join-Path $Path $LogFile
            $logType = if ($LogFile -Like "*access*") {"access"} else {"error"}
            $parser = if ($logType -eq "access") { "Parse-AccessLine" } else { "Parse-ErrorLine" }
            $lines = Get-Content $fullPath -Encoding UTF8 -ErrorAction Stop

            if ($filterActive){
                $lines = $lines | Where-Object {
                    $lineDate = Get-LineDateApache -Line $_ -LogType $logType
                    $null -ne $lineDate -and $lineDate -ge $FromDate
                }
            }
            $parsed = foreach($line in $lines){
                $obj = & $parser -Line $line
                if ($null -ne $obj){
                    $obj
                }
            }

            $weblog_result.data[$LogFile] = @{
                log_type = $logType
                count = @($parsed).Count
                entries = @($parsed)
            }

            Write-Host "[+] $LogFile`: $($lines.Count) lines"
        }
    }catch{
        Write-Host "[-] Web server logs failed: $($_.Exception.Message)"
        $weblog_result.warnings += "Web server logs failed: $($_.Exception.Message)"
    }
    return $weblog_result
}

