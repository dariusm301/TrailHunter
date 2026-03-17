function Get-WebServerLogs{
    $path = "C:\xampp\apache\logs"
    $log_files = @(
        "access.log"
        "error.log"
    )
    
    $weblog_result = @{
        data = @{}
        warnings = @()
    }

    try{
        Write-Host "[*] Collecting web server logs..."
        foreach ($log_file in $log_files){
            $full_path = "$path\$log_file"
            $weblog_result.data[$log_file] = (Get-Content $full_path -ErrorAction Stop) -join "`n"
            Write-Host "[+] $log_file`: $($weblog_result.data[$log_file].Count) lines"
        }
    }catch{
        Write-Host "[-] Web server logs failed: $($_.Exception.Message)"
        $weblog_result.warnings += "Web server logs failed: $($_.Exception.Message)"
    }
    return $weblog_result
}