function Get-Registry{

    #--- Getting registry -----
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Environment"
    )

    $registry_result = @{
        data = @{}
        warnings = @()
    }

    Write-Host "[*] Collecting Registry Keys..."
    foreach($path in $paths){
        try{
            
            $key = Get-Item -Path $path
            $registry_result.data[$path] =  $key.GetValueNames() | ForEach-Object {
                @{
                    name = $_
                    value = $key.GetValue($_)
                }
            }
            
            Write-Host "[+] $path`: $($registry_result.data[$path].Count) values"
        }
        catch{
            Write-Host "[-] Get Registry failed: $($_.Exception.Message)" -ForegroundColor Red
            $registry_result.warnings += "Get Registry failed: $($_.Exception.Message)"
        }
        
    }

    # --- Getting services ----
    try{
        $services_path = "HKLM:\System\CurrentControlSet\Services"
        $services = Get-ChildItem -Path $services_path
        $registry_result.data[$services_path] = $services | ForEach-Object{
            @{
                name = $_.PSChildName
                imagepath = $_.GetValue("ImagePath")
                start = $_.GetValue("Start")
                type = $_.GetValue("Type")
            }
        }
        Write-Host "[+] Services: $($registry_result.data[$services_path].Count) found"
    }catch{
        
        Write-Host "[-] Get services failed: $($_.Exception.Message)" -ForegroundColor Red
        $registry_result.warnings += "Get services failed: $($_.Exception.Message)"
        
    }
    Write-Host "[+] Registry collection complete"
    return $registry_result
}