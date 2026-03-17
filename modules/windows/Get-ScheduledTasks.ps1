function Get-ScheduledTasks{
    
    $task_result = @{
        tasks = @()
        warnings = @()
    }
    try{
        Write-Host "[*] Collecting scheduled tasks..."
        $task_result.tasks  = Get-ScheduledTask -ErrorAction Stop | ForEach-Object{
           $info = $_ | Get-ScheduledTaskInfo
            @{
                task_path   = $_.TaskPath
                task_name   = $_.TaskName
                state       = $_.State.ToString()
                actions     = $_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
                last_run    = $info.LastRunTime
                next_run    = $info.NextRunTime
                last_result = $info.LastTaskResult
            }
        } 
        Write-Host "[+] Scheduled Tasks: $($task_result.tasks.Count) found"
    }catch{
        Write-Host "[-] Scheduled tasks collection failed: $($_.Exception.Message)"
        $task_result.warnings += "Scheduled tasks collection failed: $($_.Exception.Message)"
    }

    return $task_result
}