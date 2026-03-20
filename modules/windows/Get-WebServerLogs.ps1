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
            $lines = Get-Content $fullPath -ErrorAction Stop

            if ($filterActive){
                $logType = if ($logFile -Like "*access*") {"access"} else {"error"}
                $lines = $lines | Where-Object {
                    $lineDate = Get-LineDateApache -Line $_ -LogType $logType
                    $null -ne $lineDate -and $lineDate -ge $FromDate
                }
            }
            $weblog_result.data[$LogFile] = $lines -join "`n"
            Write-Host "[+] $LogFile`: $($lines.Count) lines"
        }
    }catch{
        Write-Host "[-] Web server logs failed: $($_.Exception.Message)"
        $weblog_result.warnings += "Web server logs failed: $($_.Exception.Message)"
    }
    return $weblog_result
}