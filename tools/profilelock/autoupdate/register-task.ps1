# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

<#
.SYNOPSIS
Registers the daily Profile Lock Firefox update check with Task Scheduler,
and creates a Start menu shortcut for the installed build.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File register-task.ps1
#>
param(
    [string]$MozillaBuild = "C:\mozilla-build",
    [string]$At = "02:47",
    [switch]$Unregister
)

$TaskName = "Profile Lock Firefox updater"

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed '$TaskName'."
    return
}

$Python = Join-Path $MozillaBuild "python3\python3.exe"
if (-not (Test-Path $Python)) {
    throw "MozillaBuild's Python not found at $Python. Pass -MozillaBuild."
}
$Script = Join-Path $PSScriptRoot "profilelock_updater.py"

$Action = New-ScheduledTaskAction -Execute $Python -Argument "`"$Script`"" `
    -WorkingDirectory $PSScriptRoot
$Trigger = New-ScheduledTaskTrigger -Daily -At $At
# Runs only while you are logged on, as you, without storing a password.
# A missed run (computer off or asleep) happens at the next opportunity.
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 6) `
    -MultipleInstances IgnoreNew -AllowStartIfOnBatteries
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -Principal $Principal -Force | Out-Null
Write-Host "Registered '$TaskName', daily at $At."

$Install = Join-Path $env:LOCALAPPDATA "FirefoxProfileLock"
$Shortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "Firefox (Profile Lock).lnk"
$Shell = New-Object -ComObject WScript.Shell
$Link = $Shell.CreateShortcut($Shortcut)
$Link.TargetPath = Join-Path $Install "firefox.exe"
$Link.WorkingDirectory = $Install
$Link.Save()
Write-Host "Start menu shortcut: $Shortcut (works once the first build is installed)."
