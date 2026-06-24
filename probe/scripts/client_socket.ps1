param(
    [string]$ProbeIP = "172.16.0.1",    
    [int]$Port = 8000,
    [string]$Path = "/ws/control"
)

$uri = [System.Uri]::new("ws://${ProbeIP}:${Port}${Path}")
$ws = [System.Net.WebSockets.ClientWebSocket]::new()
$cts = [System.Threading.CancellationTokenSource]::new()

function Send-WsMessage {
    param($Socket, $Object, $Token)
    $json = $Object | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $segment = [System.ArraySegment[byte]]::new($bytes)
    $Socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $Token).Wait()
}

function Receive-WsMessage {
    param($Socket, $Token)
    $buffer = New-Object byte[] 8192
    $ms = New-Object System.IO.MemoryStream
    do {
        $segment = [System.ArraySegment[byte]]::new($buffer)
        $result = $Socket.ReceiveAsync($segment, $Token).GetAwaiter().GetResult()
        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            return $null
        }
        $ms.Write($buffer, 0, $result.Count)
    } while (-not $result.EndOfMessage)

    $text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
}

try {
    $ws.ConnectAsync($uri, $cts.Token).Wait()
}
catch {
    Write-Host "Error: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "Connected`n" -ForegroundColor Green

try {
    while ($ws.State -eq 'Open') {

        $msg = Receive-WsMessage -Socket $ws -Token $cts.Token
        if ($null -eq $msg) {
            Write-Host "Connection closed by the server." -ForegroundColor Yellow
            break
        }

        switch ($msg.type) {

            "menu" {
		    if ($msg.text) {
			Write-Host "`n[info] $($msg.text)" -ForegroundColor Green
		    }
		    Write-Host "`n=== $($msg.title) ===" -ForegroundColor Cyan
		    foreach ($opt in $msg.options) {
			Write-Host "  [$($opt.id)] $($opt.label)"
		    }
		    $choice = Read-Host "`nChoose an option (or 'q' for exit)"

		    if ($choice -eq "q" -or $choice -eq "exit") {
			Send-WsMessage -Socket $ws -Object @{ type = "exit" } -Token $cts.Token
		    }
		    elseif ($choice -match '^\d+$') {
			Send-WsMessage -Socket $ws -Object @{ type = "choice"; value = [int]$choice } -Token $cts.Token
		    }
		    else {
			Write-Host "Invalid option, retry." -ForegroundColor Red
		    }
		}
            "prompt" {
		    if ($msg.text -match "(?i)pass") {
			$secure = Read-Host "`n$($msg.text)" -AsSecureString
			$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
			    [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure)
			)
			Send-WsMessage -Socket $ws -Object @{ type = "input"; value = $plain } -Token $cts.Token
		    } else {
			$text = Read-Host "`n$($msg.text)"
			Send-WsMessage -Socket $ws -Object @{ type = "input"; value = $text } -Token $cts.Token
		    }
		}
	    "exec"   {
		    try {
			$output = Invoke-Expression $msg.command 2>&1 | Out-String
			$resp = @{ type = "exec_result"; success = $true; output = $output }
		    } catch {
			$resp = @{ type = "exec_result"; success = $false; output = $_.Exception.Message }
		    }
		    Send-WsMessage -Socket $ws -Object $resp -Token $cts.Token
		}

            "info" {
                Write-Host "`n[info] $($msg.text)" -ForegroundColor Green
            }
	               "error" {
                Write-Host "`n[Server error] $($msg.text)" -ForegroundColor Red
            }
	    "transfer_start" {
		    Write-Host "`nStarting transfer of $($msg.file_count) file(s)..." -ForegroundColor Cyan
		}
	"file_start" {
	    if ($script:downloadStream) {
		try { $script:downloadStream.Close() } catch {}
		$script:downloadStream = $null
	    }

	    if (-not $script:outputDir) {
		$script:outputDir = Join-Path $env:SystemDrive "TrailHunter_Extract"
		if (-not (Test-Path $script:outputDir)) {
		    New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
		}
	    }

	    $script:downloadPath = Join-Path $script:outputDir $msg.filename
	    $script:downloadStream = [System.IO.File]::Create($script:downloadPath)
	    $script:downloadTotal = $msg.size
	    $script:downloadReceived = 0
	    Write-Host "`nReceiving $($msg.filename) ($([math]::Round($msg.size/1KB,1)) KB) -> $($script:outputDir)" -ForegroundColor Cyan
	}
	"file_chunk" {
		    $bytes = [System.Convert]::FromBase64String($msg.data)
		    $script:downloadStream.Write($bytes, 0, $bytes.Length)
		    $script:downloadReceived += $bytes.Length
		    if ($script:downloadTotal -gt 0) {
			$pct = [math]::Round(($script:downloadReceived / $script:downloadTotal) * 100)
			Write-Host -NoNewline "`rProgress: $pct%   "
		    }
		}
		"file_end" {
		    $script:downloadStream.Close()
		    $localHash = (Get-FileHash -Path $script:downloadPath -Algorithm SHA256).Hash.ToLower()
		    if ($localHash -eq $msg.sha256) {
			Write-Host "`nSaved $($script:downloadPath) — hash verified OK" -ForegroundColor Green
		    } else {
			Write-Host "`nHASH MISMATCH for $($script:downloadPath)!" -ForegroundColor Red
			Write-Host "  expected: $($msg.sha256)" -ForegroundColor Red
			Write-Host "  got:      $localHash" -ForegroundColor Red
		    }
		}
		"transfer_end" {
		    Write-Host "`nAll files transferred." -ForegroundColor Green
		}

            "bye" {
                Write-Host "`nThe server closed the connection." -ForegroundColor Yellow
                break
            }

            default {
                Write-Host "[server] $($msg | ConvertTo-Json -Compress)" -ForegroundColor DarkGray
            }
        }
    }
}
catch {
	Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
	Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
}
finally {
    if ($ws.State -eq 'Open') {
        $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "client exit", $cts.Token).Wait()
    }
    $ws.Dispose()
}
