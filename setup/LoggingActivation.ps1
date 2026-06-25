#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Msg)
    Write-Host "  [OK] $Msg" -ForegroundColor Green
}

function Write-Warn2 {
    param([string]$Msg)
    Write-Host "  [!] $Msg" -ForegroundColor Yellow
}

Write-Section "Security Audit Policy"

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
Write-Ok "Process Creation auditing activated (Event ID 4688)"

$cmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $cmdLinePath)) {
    New-Item -Path $cmdLinePath -Force | Out-Null
}
New-ItemProperty -Path $cmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Ok "Command line logging in 4688 activated"

auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
Write-Ok "Logon/Logoff auditing enabled (4624, 4625, 4634)"

auditpol /set /subcategory:"Process Termination" /success:enable | Out-Null
Write-Ok "Process Termination auditing enabled (4689)"

auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
Write-Ok "Account Management auditing enabled (4720, 4728, 4732, ...)"

auditpol /set /subcategory:"Special Logon" /success:enable | Out-Null
Write-Ok "Special Logon auditing enabled (4672)"

auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
Write-Ok "Audit Policy Change auditing enabled (4719)"


Write-Section "PowerShell Logging"

$psPolicyBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

$sblPath = "$psPolicyBase\ScriptBlockLogging"
New-Item -Path $sblPath -Force | Out-Null
New-ItemProperty -Path $sblPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $sblPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Ok "Script Block Logging enabled (Event ID 4104)"

$mlPath = "$psPolicyBase\ModuleLogging"
New-Item -Path $mlPath -Force | Out-Null
New-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path "$mlPath\ModuleNames" -Force | Out-Null
New-ItemProperty -Path "$mlPath\ModuleNames" -Name "*" -Value "*" -PropertyType String -Force | Out-Null
Write-Ok "Module Logging enabled (Event ID 4103, all modules)"

$transcriptPath = "$psPolicyBase\Transcription"
$transcriptDir = "C:\PSTranscripts"
if (-not (Test-Path $transcriptDir)) {
    New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
}
New-Item -Path $transcriptPath -Force | Out-Null
New-ItemProperty -Path $transcriptPath -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $transcriptPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $transcriptPath -Name "OutputDirectory" -Value $transcriptDir -PropertyType String -Force | Out-Null
Write-Ok "PowerShell Transcription enabled (output: $transcriptDir)"

wevtutil set-log "Microsoft-Windows-PowerShell/Operational" /enabled:true /maxsize:104857600 | Out-Null
Write-Ok "Microsoft-Windows-PowerShell/Operational log enabled, max size 100MB"

wevtutil set-log "Windows PowerShell" /enabled:true | Out-Null
Write-Ok "Windows PowerShell (classic) log enabled"

Write-Section "WMI Activity Logging"

wevtutil set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /maxsize:104857600 | Out-Null
Write-Ok "Microsoft-Windows-WMI-Activity/Operational log enabled, max size 100MB"

Write-Section "Task Scheduler Logging"

wevtutil set-log "Microsoft-Windows-TaskScheduler/Operational" /enabled:true /maxsize:52428800 | Out-Null
Write-Ok "Microsoft-Windows-TaskScheduler/Operational log enabled, max size 50MB"

auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
Write-Ok "Other Object Access Events auditing enabled (4698-4702, scheduled tasks)"

Write-Section "Security Event Log Size"

wevtutil set-log "Security" /maxsize:524288000 | Out-Null
Write-Ok "Security log maximum size set to 500MB"


Write-Host "`nDone. You can quickly verify with:" -ForegroundColor Cyan
Write-Host '  auditpol /get /category:*' -ForegroundColor Gray
Write-Host '  Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-TaskScheduler/Operational"' -ForegroundColor Gray