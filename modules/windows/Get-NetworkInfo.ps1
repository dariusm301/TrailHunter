function Get-NetworkInfo{
    Write-Host "[*] Collecting network information..."

    $network_result = @{
        tcp_connections = @()
        udp_endpoints = @()
        listening_ports = @()
        arp_cache = @()
        dns_cache = @()
        interfaces = @()
        warnings = @()
        collection_time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    #---- Getting TCP connections ----
    try{
        $tcp_connections = Get-NetTCPConnection -ErrorAction Stop
        $network_result.tcp_connections = $tcp_connections | ForEach-Object{
            $processName = $null
            try{
                $processName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Name
            }catch{
                $processName = "unknown"
            }
            @{
                local_address = $_.LocalAddress
                local_port = $_.LocalPort
                remote_address = $_.RemoteAddress
                remote_port = $_.RemotePort
                state = $_.State.ToString()
                pid = $_.OwningProcess
                process_name = $processName
            }
        }
        Write-Host "[+] TCP connections: $($network_result.tcp_connections.Count) found"
    }
    catch{
        Write-Host "[-] TCP connections failed: $($_.Exception.Message)"
        $network_result.warnings += " TCP connections failed: $($_.Exception.Message)"
    }

    #--- UDP endpoints
    try {
        $udp = Get-NetUDPEndpoint -ErrorAction Stop

        $network_result.udp_endpoints = $udp | ForEach-Object {
            $processName = $null
            try {
                $processName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Name
            } catch {
                $processName = "unknown"
            }

            @{
                local_address = $_.LocalAddress
                local_port    = $_.LocalPort
                pid           = $_.OwningProcess
                process_name  = $processName
            }
        }

        Write-Host "[+] UDP endpoints: $($network_result.udp_endpoints.Count) found"
    }
    catch {
        Write-Host "[-] UDP endpoints failed: $($_.Exception.Message)" -ForegroundColor Red
        $network_result.warnings += "UDP endpoints failed: $($_.Exception.Message)"
    }

    #--- Listening ports ----
    try{
        $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop

        $network_result.listening_ports = $listening | ForEach-Object{
            $processName = $null
            try{
                $processName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Name
            }catch{
                $processName = "unknown"
            }

            @{
                local_address = $_.LocalAddress
                local_port = $_.LocalPort
                pid = $_.OwningProcess
                process_name = $processName
            }
        }
        Write-Host "[+] Listening ports: $($network_result.listening_ports.Count) found"

    }catch{
        Write-Host "[-] Listening ports failed: $($_.Exception.Message)"
        $network_result.warnings += "Listening ports failed: $($_.Exception.Message)"
    }
    #--- ARP Cache ----
    try{
        $arp = Get-NetNeighbor -ErrorAction Stop

        $network_result.arp_cache = $arp | ForEach-Object{
            @{
                ip_address = $_.IPAddress
                mac_address = $_.LinkLayerAddress
                state = $_.State.ToString()
                interface = $_.InterfaceAlias
            }
        }
        Write-Host "[+] ARP cache: $($network_result.arp_cache.Count) entries"
    }catch{
        Write-Host "[-] ARP Cache failed: $($_.Exception.Message)"
        $network_result.warnings += "ARP cache failed: $($_.Exception.Message)"
    }

    # --- DNS cache ------
     try {
        $dns = Get-DnsClientCache -ErrorAction Stop

        $network_result.dns_cache = $dns | ForEach-Object {
            @{
                entry      = $_.Entry
                record_name = $_.RecordName
                data       = $_.Data
                ttl        = $_.TimeToLive
            }
        }

        Write-Host "[+] DNS cache: $($network_result.dns_cache.Count) entries"
    }
    catch {
        Write-Host "[-] DNS cache failed: $($_.Exception.Message)" -ForegroundColor Red
        $network_result.warnings += "DNS cache failed: $($_.Exception.Message)"
    }

    # ─── Network Interfaces ────────────────────────────────
    try {
        $interfaces = Get-NetIPConfiguration -ErrorAction Stop

        $network_result.interfaces = $interfaces | ForEach-Object {
            @{
                interface     = $_.InterfaceAlias
                ip_address    = $_.IPv4Address.IPAddress
                gateway       = $_.IPv4DefaultGateway.NextHop
                dns_servers   = $_.DNSServer.ServerAddresses
            }
        }

        Write-Host "[+] Interfaces: $($network_result.interfaces.Count) found"
    }
    catch {
        Write-Host "[-] Interfaces failed: $($_.Exception.Message)" -ForegroundColor Red
        $network_result.warnings += "Interfaces failed: $($_.Exception.Message)"
    }
    return $network_result
}