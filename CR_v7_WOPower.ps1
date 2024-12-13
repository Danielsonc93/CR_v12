#cr_v6_WOSLPversion 1 :::For Offline PCs, no sleep settings:: 2024 Dec 13





$softwareList = @("FileZilla", "Splashtop", "PuTTY", "AnyDesk", "Wireshark", "OpenVPN", "FortiClient", "Malwarebytes", "NordVPN", "RealVNC", "RemotePC", "VNCViewer", "PsExec", "Advanced IP Scanner", "Advanced Port Scanner", "Nmap", "Bomgar", "TightVNC", "360", "Chrome Remote Desktop", "WinSCP", "LogMeIn", "McAfee")


$r = @();
$l = @("User", "System", "WoW");
$e = @("HKCU:\Software\", "HKLM:\Software\", "HKLM:\Software\Wow6432Node\");
$f = @("", "common ");

foreach ($i in 0..2) {
  $k = get-item ($e[$i] + "Microsoft\Windows\CurrentVersion\Run");
  ($k.getvaluenames() |%{
    $r += [pscustomobject]@{ l = "Run:" + $l[$i]; n = $_; c = $k.getvalue($_) }
  })
};

foreach ($i in 0..1) {
  ((new-object -com shell.application).namespace("shell:" + $f[$i] + "startup").items() |%{
    $r += [pscustomobject]@{ l = "Startup:" + $l[$i]; n = $_.name; c = $_.path }
  })
};

$x = get-itemproperty ("HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\*"), ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\*");

$nuwp = ($r |? c -ne "" |%{
  $o = [pscustomobject]@{ location = $_.l; name = $_.n; disabled = 0; command = $_.c; path = $null };
  $x |%{
    $p = $_.PSPath;
    $_ | get-member -type noteproperty |? name -eq $o.name |%{
      $v = get-itempropertyvalue $p -name $o.name;
      $o.path = $p;
      $o.disabled = $v[0] -band 1
    }
  };
  $o
});

$uwp = (get-appxpackage |% {
  $x = $_;
  $t = (get-appxpackagemanifest $_).package.applications.application.extensions.extension |? category -eq "windows.startuptask";
  if ($t -ne $null) {
    $p = "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\" + $x.packagefamilyname + "\" + $t.startuptask.taskid;
    $s = (get-item $p).getvalue("state");
    $o = [pscustomobject]@{ location = "UWP"; name = $x.name; disabled = $s -band 1; command = $x.installlocation + "\" + $t.executable; path = $p };
    $o
  }
});

$nuwp+$uwp |% {
  $disable = $false
  foreach ($software in $softwareList) {
    $softwareNoSpaces = $software -replace " "
    if ($_.name -replace " " -match [regex]::Escape($softwareNoSpaces)) {
      $disable = $true
      break
    }
  }
  if ($disable) {
    if ($_.location -eq "UWP") {
      set-itemproperty -path $_.path -name "state" -value 1
    } else {
      set-itemproperty -path $_.path -name $_.name -value 1
    }
  }
}


$computerName = $env:COMPUTERNAME
$uninstallKey64 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$uninstallKey32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$uninstallKeyUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"

$apps64 = Get-ItemProperty $uninstallKey64 -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName
$apps32 = Get-ItemProperty $uninstallKey32 -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName
$appsUser = Get-ItemProperty $uninstallKeyUser -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName
$allApps = $apps64 + $apps32 + $appsUser

foreach ($softwareName in $softwareList) {
    $software = $allApps | Where-Object { $_.DisplayName -like "*$softwareName*" }

    if ($software) {
        foreach ($app in $software) {
            $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($app.PSChildName)"
            if (-not (Test-Path $uninstallKey -ErrorAction SilentlyContinue)) {
                $uninstallKey = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($app.PSChildName)"
            }
            if (-not (Test-Path $uninstallKey -ErrorAction SilentlyContinue)) {
                $uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($app.PSChildName)"
            }
            $uninstallString = (Get-ItemProperty $uninstallKey -ErrorAction SilentlyContinue).UninstallString
            if ($uninstallString) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallString /quiet" -WindowStyle Hidden -Wait
            }
        }
    } else {
        $installedSoftware = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%$softwareName%'" -ErrorAction SilentlyContinue
        if ($installedSoftware) {
            $wmicUninstall = "wmic product where ""name like '%$softwareName%'"" call uninstall /nointeractive"
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $wmicUninstall" -WindowStyle Hidden -Wait
        } else {
            $softwares = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$softwareName*" }
            if ($softwares) {
                foreach ($software in $softwares) {
                    $software.Uninstall() | Out-Null
                }
            }
        }
    }
}



foreach ($software in $softwareList) {
  # Paths to be checked and removed
  $paths = @(
    "$env:USERPROFILE\Downloads\*$software*",
    "C:\Program Files (x86)\*$software*",
    "C:\ProgramData\*$software*",
    "C:\Users\$env:USERNAME\AppData\Roaming\*$software*",
    "C:\Users\$env:USERNAME\AppData\Local\Temp\*$software*",
    "HKCU:\Software\*$software*",
    "HKLM:\Software\*$software*"
  )
  foreach ($path in $paths) {
    if (Test-Path $path) {
      Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  # Stop services, terminate processes, and disable startup apps
  if (Get-Service -Name "$software" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "$software" -ErrorAction SilentlyContinue
  }
  if (Get-Process -Name "$software" -ErrorAction SilentlyContinue) {
    Get-Process -Name "$software" | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  Get-CimInstance -ClassName Win32_StartupCommand | Where-Object { $_.Name -like "*$software*" } | Remove-CimInstance -ErrorAction SilentlyContinue
}




$deletedFolders = @()
$notFoundFolders = @()

$folderName1 = "AnyDesk"
$searchPaths1 = @("C:\Users\myroot\OneDrive - RST Instruments\Backup\OldPCs\NB003\dewusi\*\*", "C:\Users\*\*\*", "C:\Users\wvaldez\*\*", "C:\Users\mproot\*\*", "C:\Users\myroot\*\*", "C:\Users\kizmaylov\*\*", "C:\Windows\SysWOW64\config\systemprofile\*\*", "C:\Program Files (x86)", "C:\Users\myagi\*\*", "C:\Users\myagi\OneDrive - RST Instruments\Backup\OldPCs\NB003\dewusi\*\*", "C:\Users\mpalgov\*\*", "C:\Users\egilboe.TERRAINSIGHTS\*\*", "C:\Users\SMansooribaniani\*\*", "C:\Users\mplummer\*\*", "C:\Users\calibration1\*\*", "C:\Users\pvazhoor\*\*")

$folderName2 = "Bomgar*"
$searchPaths2 = @("C:\Users\ljourdain.TERRAINSIGHTS\OneDrive - RST Instruments\P Drive Backup\NB066_Final\Users\ljourdain\Downloads", "C:\Users\ljourdain.TERRAINSIGHTS\OneDrive - terrainsights\P Drive Backup\NB066_Final\Users\ljourdain\Downloads", "C:\Users\ljourdain.TERRAINSIGHTS\Terra Insights\Lise Jourdain - Documents\Downloads", "C:\Users\ljourdain.TERRAINSIGHTS\Terra Insights\Lise Jourdain - Documents\NB066_Final\Users\ljourdain\Downloads", "C:\Users\bhowarth.TERRAINSIGHTS\Downloads", "C:\Users\gdu\Downloads", "C:\Users\myroot\OneDrive - RST Instruments\Backup\OldPCs\PC040\Users\GDu\Downloads")

$folderName3 = "PuTTY"
$searchPaths3 = @("C:\Program Files")

$Delete_FolderIfFoundComputers1 = @("LB-SRV-001", "NB047", "NB055", "NB065", "NB066", "NB131", "NB144", "NB182", "NB187", "PC004", "PC007", "PC010", "PC034", "PC040")
$Delete_FolderIfFoundComputers2 = @("NB139", "NB191", "PC040")
$Delete_FolderIfFoundComputers3 = @("NB214")

function Delete-FolderIfFound {
    param (
        [string]$folderName,
        [array]$searchPaths,
        [array]$computerLists
    )

    if ($computerLists -contains $computerName) {
        foreach ($searchPath in $searchPaths) {
            $fullPath = Join-Path -Path $searchPath -ChildPath $folderName

            if (Test-Path -Path $fullPath) {
                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Delete-FolderIfFound -folderName $folderName1 -searchPaths $searchPaths1 -computerLists $Delete_FolderIfFoundComputers1
Delete-FolderIfFound -folderName $folderName2 -searchPaths $searchPaths2 -computerLists $Delete_FolderIfFoundComputers2
Delete-FolderIfFound -folderName $folderName3 -searchPaths $searchPaths3 -computerLists $Delete_FolderIfFoundComputers3


$filedeletepath1 = "C:\Program Files (x86)\Battle.net"  
$filedeletepath2 = "C:\Program Files\Everything"        
$filedeletepath3 = "C:\Users\hkyi\OneDrive - Terra Insights\Abracadabra - Copy"

$FiledeleteComputers1 = @("NB046")                      
$FiledeleteComputers2 = @("NB138")                      
$FiledeleteComputers3 = @("NB214")

function Delete-ItemIfComputerInList {
    param (
        [string]$itemPath,
        [array]$computerList
    )

    if ($computerList -contains $computerName) {
        if (Test-Path -Path $itemPath) {
            Remove-Item -Path $itemPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Delete-ItemIfComputerInList -itemPath $filedeletepath1 -computerList $FiledeleteComputers1
Delete-ItemIfComputerInList -itemPath $filedeletepath2 -computerList $FiledeleteComputers2
Delete-ItemIfComputerInList -itemPath $filedeletepath3 -computerList $FiledeleteComputers3



$disabledFeatures = @()
$attentionNeeded = @()
$noChanges = @()
$uninstalledFeatures = @()

Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -Remove

$optionalFeatureStatus = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | findstr "State"

if ($optionalFeatureStatus -match "State\s*:\s*Disabled") {
    $disabledFeatures += "PS Status :: Disabled :: $computerName.$domain"
} else {
    $OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

    switch -regex ($OSVersion) {  
        "(?i)10|2012|2016|2019" {
            $PSv2PreCheck = dism.exe /Online /Get-Featureinfo /FeatureName:"MicrosoftWindowsPowerShellv2" | findstr "State"
            If ($PSv2PreCheck -like "State : Enabled") {
                dism.exe /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellv2" /NoRestart
                $PSv2PostCheck = dism.exe /Online /Get-Featureinfo /FeatureName:"MicrosoftWindowsPowerShellv2" | findstr "State"
                If ($PSv2PostCheck -like "State : Enabled") {
                    $attentionNeeded += "PS2 needs attention, can't be disabled :: $computerName"
                } Else {
                    $disabledFeatures += "PS Status :: Disabled :: $computerName.$domain"
                }
            } Else {
                $disabledFeatures += "PS Status :: Disabled :: $computerName.$domain"
            }
        }   
        "(?i)7|Vista|2008" {
            $noChanges += "Detected Windows 7/Vista/Server 2008, no changes will be made."
        }
        "(?i)Windows Server" {
            Uninstall-WindowsFeature -Name PowerShell-V2
            Get-WindowsFeature -Name PowerShell* | Select-Object -ExpandProperty InstallState
        }
        default {
            $computerFeatureStatus = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root | Select-Object -ExpandProperty State

            $disabledFeatures += "Status :: $computerFeatureStatus :: $computerName.$domain"
        }
    }
}



$KPcompletionLogPath = "\\rst-mpr-fps01.rst.local\IT Temp\KP_completion_report_log.txt"
$keePassInstallerUrl = "https://drive.google.com/uc?export=download&id=1HfLxZH2DJqwIUoGS-jNmGQ7J3X4g5kIc"
$downloadPath = "$env:USERPROFILE\Downloads\KeePass-2.57.1-Setup.exe"
$tempDownloadPath = "C:\Temp\KeePass-2.57.1-Setup.exe"

$keePassSoftware = "KeePass"

$optOutComputers = @("terra-dc", "RST-MPR-DC01", "COLE", "PETROV", "RST-101", "RST-MPR-ADFS", "RST-MPR-APP01", "RST-MPR-APP02", "RST-MPR-APP03", "RST-MPR-FPS01", "RST-MPR-RDS", "RST-MPR-RDSH01", "RST-MPR-RDSH02", "RST-MPR-SQL01", "RST-MPR-WAP", "TERRAKINETICAPP", "TERRAKINETICDB", "CUNDERWOOD2", "TERRAKINETICDC")

if ($optOutComputers -notcontains $computerName) {
    
    $keePassFound = $allApps | Where-Object { $_.DisplayName -like "*$keePassSoftware*" }

    if (-not $keePassFound) {
        $installedKeePass = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%$keePassSoftware%'"
        if (-not $installedKeePass) {
            
            try {
                if (Test-Path "$env:USERPROFILE\Downloads") {
                    Invoke-WebRequest -Uri $keePassInstallerUrl -OutFile $downloadPath
                    $installerPath = $downloadPath
                } else {
                    throw "Downloads folder not available"
                }
            } catch {
                if (-not (Test-Path "C:\Temp")) {
                    New-Item -ItemType Directory -Path "C:\Temp"
                }
                Invoke-WebRequest -Uri $keePassInstallerUrl -OutFile $tempDownloadPath
                $installerPath = $tempDownloadPath
            }

            $process = Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT" -NoNewWindow -PassThru
            Wait-Process -Id $process.Id
            if (Test-Path $KPcompletionLogPath) {
                Add-Content -Path $KPcompletionLogPath -Value "KeePass installed :: $computerName"
            }

            if (Test-Path $installerPath) {
                Remove-Item $installerPath
            }
        }
    }
} else {
    if (Test-Path $KPcompletionLogPath) {
        Add-Content -Path $KPcompletionLogPath -Value "KeePass installation skipped on $computerName"
    }
}



