<#



.DESCRIPTION
    PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server).  
	
	It's recommended to run this script with administrative privileges to get more Artifacts. Nevertheless, if not possible, some artificats will be collected.

    The collected information is saved in an output directory in the current folder, this is by creating a folder named 'PowerTriage-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end to enable easy Collecting.


.NOTES
Requires administrative privileges to run.
Creates an output directory with the current date and hostname.
    
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [switch]$folder
)
clear

#Variable to hide error messages when Recent Items Function is executed
$ErrorActionPreference = "SilentlyContinue"

$Version = '1.5'
$ASCIIBanner = @"
 ____                       _____     _                  
|  _ \ _____      _____ _ _|_   _| __(_) __ _  __ _  ___ 
| |_) / _ \ \ /\ / / _ \ '__|| || '__| |/ _` |/ _` |/ _ \
|  __/ (_) \ V  V /  __/ |   | || |  | | (_| | (_| |  __/
|_|   \___/ \_/\_/ \___|_|   |_||_|  |_|\__,_|\__, |\___|
                                              |___/      `n
"@
Write-Host $ASCIIBanner
Write-Host "PowerTriage is a script to perform incident response via PowerShell on compromised devices with an Windows Operating System (Workstation & Server)." 
Write-Host "Version: $Version"
Write-Host "By twitter 'X': @jdangosto, Github: https://github.com/jdangosto - Jesus Angosto (jdangosto)"
Write-Host "=================================================================================================================================================`n"

#Check Admin Privileges

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)


if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator...`n"
}
else {
    Write-Host "No Administrator session detected. For the best performance run as Administrator. Not all items can be collected...`n" -ForegroundColor Red
    #Start-Sleep -Seconds 3
    Exit
}


If ($folder){
    $path = $folder
    $ExecutionTime = $(get-date -f yyyyMMdd_HHmmsstt)
    Write-Host "Running task 1 of 28" -ForegroundColor Yellow
    Write-Host "Creating output directory...`n"
    $FolderCreation = "$path\PowerTriage-$env:computername-$ExecutionTime" 
    Write-Host $FolderCreation
    mkdir -Force $FolderCreation | Out-Null
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Write-Host "                               Output directory created: $FolderCreation...`n" -ForegroundColor Green
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
   # Start-Sleep -Seconds 3
   
}else{
    $path = "C:\"
    $ExecutionTime = $(get-date -f yyyyMMdd_HHmmsstt)
    Write-Host "Running task 1 of 28" -ForegroundColor Yellow
    Write-Host "Creating output directory...`n"
    $FolderCreation = "$path\PowerTriage-$env:computername-$ExecutionTime"
    Write-Host $FolderCreation
    mkdir -Force $FolderCreation | Out-Null
   
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
    Write-Host "                               Output directory created: $FolderCreation...`n" -ForegroundColor Green
    Write-Host "==========================================================================================================================================`n" -ForegroundColor Green
   # Start-Sleep -Seconds 3
   
}


#System Info
Write-Host "Running task 2 of 28" -ForegroundColor Yellow
Write-Host "Collecting System Information...`n"
 mkdir -Force $FolderCreation\System\ | Out-Null
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors | Out-File -FilePath $FolderCreation\System\system_info.txt

#Ip del sistema
Write-Host "Running task 3 of 28" -ForegroundColor Yellow
Write-Host "Collecting IP Address...`n"
 mkdir -Force $FolderCreation\Network\ | Out-Null
Get-NetIPAddress | Out-File -FilePath $FolderCreation\Network\ip_info.txt

#Conexiones abiertas y establecidas
Write-Host "Running task 4 of 28" -ForegroundColor Yellow
Write-Host "Collecting open and stablished TCP conecctions...`n"
Get-NetTCPConnection -state Established | Out-File -FilePath $FolderCreation\Network\TCP_Stablished_Connections.txt

#Listado de Shadow Copies
WriteLog -Level "INFO" Write-Host "Running task 5 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting List of existing shadow copies...`n"
Get-CimInstance Win32_ShadowCopy | Out-File -FilePath $FolderCreation\System\Shadow_Copies_list.txt

#persistencia en Autorun
WriteLog -Level "INFO" Write-Host "Running task 6 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting Autorun info...`n"
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force $FolderCreation\System\Autoruns.txt

#Usuarios activos
WriteLog -Level "INFO" Write-Host "Running task 7 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting Active user/s on system...`n"
 mkdir -Force $FolderCreation\Users\ | Out-Null
query user | Out-File -FilePath $FolderCreation\Users\Active_users.txt

#Usuarios locales
WriteLog -Level "INFO" Write-Host "Running task 8 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting local users...`n"
Get-LocalUser | format-table | Out-File -FilePath $FolderCreation\Users\Local_Users.txt
#Usuarios obtenidos de consulta al registro con SIDs
Get-ChildItem -Path "registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Out-File -Force -FilePath $FolderCreation\Users\Users_full_regedit.txt


function Get-ProcessAndHashes {
   Write-Host "Running task 9 of 28" -ForegroundColor Yellow
   Write-Host "Collecting Active Processes...`n"
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$CSVExportLocation = "$ProcessFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $CSVExportLocation
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}


function Print-ProcessTree() { 

 Write-Host "Running task 10 of 28" -ForegroundColor Yellow
 Write-Host "Collecting Process Tree (Parent & Child)...`n"

    function Get-ProcessAndChildProcesses($Level, $Process) { 

        "{0}[{1,-5}] [{2}]" -f ("  " * $Level), $Process.ProcessId, $Process.Name 

        $Children = $AllProcesses | where-object {$_.ParentProcessId -eq $Process.ProcessId -and $_.CreationDate -ge $Process.CreationDate} 

        if ($null -ne $Children) { 

            foreach ($Child in $Children) { 

                Get-ProcessAndChildProcesses ($Level + 1) $Child 

            } 

        } 

    } 

  

    $AllProcesses = Get-CimInstance -ClassName "win32_process" 

    $RootProcesses = @() 

    # Process "System Idle Process" is processed differently, as ProcessId and ParentProcessId are 0 

    # $AllProcesses is sliced from index 1 to the end of the array 

    foreach ($Process in $AllProcesses[1..($AllProcesses.length-1)]) { 

        $Parent = $AllProcesses | where-object {$_.ProcessId -eq $Process.ParentProcessId -and $_.CreationDate -lt $Process.CreationDate} 

        if ($null -eq $Parent) { 

            $RootProcesses += $Process 

        } 

    } 

    # Process the "System Idle process" separately 

    "[{0,-5}] [{1}]" -f $AllProcesses[0].ProcessId, $AllProcesses[0].Name 

    foreach ($Process in $RootProcesses) { 

        Get-ProcessAndChildProcesses 0 $Process 

    } 

} 

function Get-Evtx {
   Write-Host "Running task 11 of 28" -ForegroundColor Yellow
   Write-Host "Collecting System Events(evtx) Files...`n"
    $EventViewer = "$FolderCreation\EventsLogs"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-NTLM/Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels} | ForEach-Object{
        Copy-Item  -Path $_.FullName -Destination "$($EventViewer)\$($_.Name)"
    }
}

#Obtención de procesos
Get-ProcessAndHashes
Print-ProcessTree | Out-File -Force $FolderCreation\ProcessInformation\ProcessTree.txt

#Obtencion de Eventos de sistema: Aplicación, Sistema, Seguridad, Sysmon, Tareas Programadas, Powershell Operational
Get-Evtx

#comandos powershell de todos los usuarios
function PowerShell_Commands{
Write-Host "Running task 12 of 28" -ForegroundColor Yellow
Write-Host "Collecting Console Powershell History (all users)...`n"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    #WriteLog -Level "INFO" Write-Host "Directorio: " $PowershellConsoleHistory
    # Directorio de los usuarios
    
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
    

}

PowerShell_Commands

#Tareas Programadas
WriteLog -Level "INFO" Write-Host "Running task 13 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting Schedule Tasks and Tasks run info...`n"
$ScheduleFolder = "$FolderCreation\ScheduleTask"
mkdir -Force $ScheduleFolder | Out-Null
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ScheduleFolder\ScheduleTask_list.txt
WriteLog -Level "INFO" Write-Host "Running task 14 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting Schedule Tasks Run Info...`n"
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ScheduleFolder\ScheduleTask_RunInfo.txt

#Servicios
WriteLog -Level "INFO" Write-Host "Running task 15 of 28" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "Collecting running services...`n"
Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-file -Force -FilePath $FolderCreation\System\Services_Running.txt


#PowerShell Console History todos los usuarios

function Get-PowershellHistory {
   Write-Host "Running task 16 of 28" -ForegroundColor Yellow
   Write-Host "Collecting Console Powershell History All Users...`n"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
}    

Get-PowershellHistory

#Elementos Recientes
function RecentFiles{
Write-Host "Running task 17 of 28" -ForegroundColor Yellow
Write-Host "Collecting Recent Items (all users)...`n"
    $Recent = "$FolderCreation\Recent_Items"
    #WriteLog -Level "INFO" Write-Host "Directorio: " $Recent
    # Directorio de los usuarios
    #mkdir -Force $Recent | Out-Null
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $RecentFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Recent\*"
        #WriteLog -Level "INFO" Write-Host $RecentFilePath
        #WriteLog -Level "INFO" Write-Host $userName
        $origen = $RecentFilePath
        $destino = "$Recent\$userName"
        #WriteLog -Level "INFO" Write-Host $origen "--" $destino
        
            Copy-Item "$origen" -Destination "$destino"
        }
}
RecentFiles


#ActivitiesCache all Users
function ActivitiesCache{
Write-Host "Running task 18 of 28" -ForegroundColor Yellow
Write-Host "Collecting Recent Items (all users)...`n"
    $Recent = "$FolderCreation\Activities_Cache"
    $usersDirectory = "C:\Users"
    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
   
        $userName = $userDir.Name
        $RecentFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Local\ConnectedDevicesPlatform\*"
        #WriteLog -Level "INFO" Write-Host $RecentFilePath
        #WriteLog -Level "INFO" Write-Host $userName
        $origen = $RecentFilePath
        $destino = "$Recent\$userName"
        #WriteLog -Level "INFO" Write-Host $origen "--" $destino
      try{
            Copy-Item "$origen" -Destination "$destino" -Force -Recurse
       }
       catch{Write-Host "User $userName hasn't ActivitiesCache file"}

        }
}
ActivitiesCache

#Copia de Prefecth
function CopyPrefetch{
 Write-Host "Running task 19 of 28" -ForegroundColor Yellow
 Write-Host "Collecting Prefetch...`n"
  $origen = "C:\Windows\Prefetch"
  $destino = "$FolderCreation\Prefetch"
  Copy-Item -Path "$origen" -Destination "$destino" -Force -Recurse
}
CopyPrefetch

#RecycleBin All Users
function RecycleBin{

   Write-Host "Running task 20 of 28" -ForegroundColor Yellow
   Write-Host "Collecting Recycle.Bin (all users)...`n"
    $origen = "C:\`$Recycle.Bin"
    $destino = "$FolderCreation\RecycleBin"
    Copy-Item -Path "$origen" -Destination "$destino" -Force -Recurse
   
}
RecycleBin

function Get-DNS {
   Write-Host "Running task 21 of 28" -ForegroundColor Yellow
   Write-Host "Collecting DNS Cache...`n"
    $destino = "$FolderCreation\Network\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $destino
	
}
Get-DNS


function Installed_Software{
   Write-Host "Running task 22 of 28" -ForegroundColor Yellow
   Write-Host "Collecting Installed Software...`n"
    $destino = "$FolderCreation\Installed_Software"
    Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version, InstallDate | Sort-Object Name | Out-File $destino\Win32_Product_Software.txt
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Out-File $destino\Software_with_Unistall.txt


}


#### COMMON BROWSERS

function CheckAndCloseBrowsers {
    # Nombres de los procesos de los navegadores
    $browsers = @("msedge", "firefox", "brave", "chrome", "opera")

     Write-Host "*******************************************************************************`n" -ForegroundColor Yellow
     Write-Host "                     Cheking if any Browser is running...                      `n" -ForegroundColor Yellow
     Write-Host "`n"
     Write-Host "            If it is open, it will be closed to collect artifacts              `n" -ForegroundColor Yellow
     Write-Host "*******************************************************************************`n" -ForegroundColor Yellow
     Start-Sleep -Seconds 3

    foreach ($browser in $browsers) {
        # Comprobar si el navegador está en ejecución
        $browserProcesses = Get-Process -Name $browser -ErrorAction SilentlyContinue

        if ($browserProcesses) {
           Write-Host "$browser is running. Proceeding to close it..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            
            # Finalizar el proceso del navegador
            Stop-Process -Name $browser -Force
            
           Write-Host "$browser has been closed." -ForegroundColor Green
        } else {
           Write-Host "$browser is not running." -ForegroundColor Cyan
        }
    }
}

# Llamar a la función
CheckAndCloseBrowsers



function FirefoxArtifacts {
   Write-Host "Running task 23 of 28" -ForegroundColor Yellow
    $usersDirectory = "C:\Users"
    $DestinoBase = "$FolderCreation\Browsers\Firefox"

    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory

    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        
        # Compruebo si Firefox existe
        if (Test-Path "C:\Users\$userName\AppData\Roaming\Mozilla\Firefox") {
           Write-Host "Collecting Firefox's Sqlite files for $userName...`n" -ForegroundColor Cyan

            # Verifica si el directorio de perfiles de Firefox existe
            $firefoxProfilesPath = "C:\Users\$userName\AppData\Roaming\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                # Crear un directorio específico para cada usuario
                $DestinoUsuario = Join-Path -Path $DestinoBase -ChildPath $userName
                New-Item -Path $DestinoUsuario -ItemType Directory -Force | Out-Null

                # Copiar archivos SQLite
                Get-ChildItem -Path $firefoxProfilesPath -Recurse -Filter *.sqlite -ErrorAction SilentlyContinue | 
                Where-Object { $_.BaseName -in @('cookies', 'formhistory', 'permissions', 'places', 'protections', 'storage', 'webappsstore') } | 
                ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$DestinoUsuario\$($_.Name)"
                }
            } else {
               Write-Host "No Firefox's profile found for $userName" -ForegroundColor Red
            }
        } else {
           Write-Host "Firefox isn't installed for $userName" -ForegroundColor Red
        }
    }
}
FirefoxArtifacts

function OperaArtifacts {
   Write-Host "Running task 24 of 28" -ForegroundColor Yellow
    $usersDirectory = "C:\Users"
    $DestinoBase = "$FolderCreation\Browsers\Opera"

    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory

    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        
        # Compruebo si Opera existe
        if (Test-Path "C:\Users\$userName\AppData\Roaming\Opera Software\") {
           Write-Host "Collecting Opera's files for $userName...`n"  -ForegroundColor Green

            # Verifica si el directorio de perfiles de Opera existe
            $OperaProfilesPath = "C:\Users\$userName\AppData\Roaming\Opera Software\Opera Stable\Default"
            if (Test-Path $OperaProfilesPath) {
                # Crear un directorio específico para cada usuario
                $DestinoUsuario = Join-Path -Path $DestinoBase -ChildPath $userName
                New-Item -Path $DestinoUsuario -ItemType Directory -Force | Out-Null

                # Copiar archivos dat
                Get-ChildItem -Path $OperaProfilesPath -Recurse  -ErrorAction SilentlyContinue | 
                Where-Object { $_.BaseName -in @('Bookmarks', 'Favicons', 'History', 'Visited Links') } | 
                ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$DestinoUsuario\$($_.Name)"
                }
                #Cookie
                Copy-Item -Path "$OperaProfilesPath\Network\Cookies" -Destination $DestinoUsuario -Force -Recurse
                #cache
                Copy-Item -Path "$OperaProfilesPath\Cache" -Destination $DestinoUsuario -Force -Recurse
            } else {
               Write-Host "No Opera's profile found for $userName" -ForegroundColor Red
            }
        } else {
           Write-Host "Opera isn't installed for $userName" -ForegroundColor Red
        }
    }
}


OperaArtifacts


function EdgeArtifacts {
    Write-Host "Running task 25 of 28" -ForegroundColor Yellow
    $usersDirectory = "C:\Users"
    $DestinoBase = "$FolderCreation\Browsers\Edge"

    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory

    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        
        # Compruebo si Edge existe
        if (Test-Path "C:\Users\$userName\AppData\Local\Microsoft\") {
           Write-Host "Collecting Edge's files for $userName...`n" -ForegroundColor Cyan

            # Verifica si el directorio de perfiles de Edge existe
            $EdgeProfilesPath = "C:\Users\$userName\AppData\Local\Microsoft\Edge\User Data\Default"
            if (Test-Path $EdgeProfilesPath) {
                # Crear un directorio específico para cada usuario
                $DestinoUsuario = Join-Path -Path $DestinoBase -ChildPath $userName
                New-Item -Path $DestinoUsuario -ItemType Directory -Force | Out-Null

                # Copiar archivos
                Get-ChildItem -Path $EdgeProfilesPath -Recurse  -ErrorAction SilentlyContinue | 
                Where-Object { $_.BaseName -in @('Bookmarks', 'Favicons', 'History', 'Visited Links') } | 
                ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$DestinoUsuario\$($_.Name)"
                }
                #Cooke
                Copy-Item -Path "$EdgeProfilesPath\Network\Cookies" -Destination $DestinoUsuario -Force -Recurse
                #cache
                Copy-Item -Path "$EdgeProfilesPath\Cache" -Destination $DestinoUsuario -Force -Recurse

            } else {
               Write-Host "No Edge's profile found for $userName" -ForegroundColor Red
            }
        } else {
           Write-Host "Edge isn't installed for $userName `n" -ForegroundColor Red
        }
    }
}
EdgeArtifacts

function ChromeArtifacts {
    Write-Host "Running task 26 of 28" -ForegroundColor Yellow
    $usersDirectory = "C:\Users"
    $DestinoBase = "$FolderCreation\Browsers\Chrome"

    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory

    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        
        # Compruebo si Chrome existe
        if (Test-Path "C:\Users\$userName\AppData\Local\Google") {
           Write-Host "Collecting Chrome files for $userName...`n" -ForegroundColor Cyan

            # Verifica si el directorio de perfiles de Chrome existe
            $ChromeProfilesPath = "C:\Users\$userName\AppData\Local\Google\Chrome\User Data\Default"
            if (Test-Path $ChromeProfilesPath) {
                # Crear un directorio específico para cada usuario
                $DestinoUsuario = Join-Path -Path $DestinoBase -ChildPath $userName
                New-Item -Path $DestinoUsuario -ItemType Directory -Force | Out-Null

                # Copiar archivos
                Get-ChildItem -Path $ChromeProfilesPath -Recurse  -ErrorAction SilentlyContinue | 
                Where-Object { $_.BaseName -in @('Bookmarks', 'Favicons', 'History', 'Visited Links') } | 
                ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$DestinoUsuario\$($_.Name)"
                }
                #Cooke
                Copy-Item -Path "$ChromeProfilesPath\Network\Cookies" -Destination $DestinoUsuario -Force -Recurse
                #cache
                Copy-Item -Path "$ChromeProfilesPath\Cache" -Destination $DestinoUsuario -Force -Recurse

            } else {
               Write-Host "No Chrome profile found for $userName" -ForegroundColor Red
            }
        } else {
           Write-Host "Chrome isn't installed for $userName `n" -ForegroundColor Red
        }
    }
}

ChromeArtifacts

function BraveArtifacts {
    Write-Host "Running task 27 of 28" -ForegroundColor Yellow
    $usersDirectory = "C:\Users"
    $DestinoBase = "$FolderCreation\Browsers\Brave"

    # Listado de directorio de usuarios en C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory

    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        
        # Compruebo si Brave existe
        if (Test-Path "C:\Users\$userName\AppData\Local\BraveSoftware\Brave-Browser\User Data") {
           Write-Host "Collecting Brave files for $userName...`n" -ForegroundColor Cyan

            # Verifica si el directorio de perfiles de Brave existe
            $BraveProfilesPath = "C:\Users\$userName\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
            if (Test-Path $BraveProfilesPath) {
                # Crear un directorio específico para cada usuario
                $DestinoUsuario = Join-Path -Path $DestinoBase -ChildPath $userName
                New-Item -Path $DestinoUsuario -ItemType Directory -Force | Out-Null

                # Copiar archivos
                Get-ChildItem -Path $BraveProfilesPath -Recurse  -ErrorAction SilentlyContinue | 
                Where-Object { $_.BaseName -in @('Bookmarks', 'Favicons', 'History', 'Visited Links') } | 
                ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$DestinoUsuario\$($_.Name)"
                }
                #Cooke
                Copy-Item -Path "$BraveProfilesPath\Network\Cookies" -Destination $DestinoUsuario -Force -Recurse
                #cache
                Copy-Item -Path "$BraveProfilesPath\Cache" -Destination $DestinoUsuario -Force -Recurse

            } else {
               Write-Host "No Brave profile found for $userName" -ForegroundColor Red
            }
        } else {
           Write-Host "Brave isn't installed for $userName `n" -ForegroundColor Red
        }
    }
}

BraveArtifacts

function Get-RdpConnectios{
 $RawEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" | `
        Where-Object { $_.Id -eq 1149 }

    $RawEvents | ForEach-Object `
    {  
        if ($_.Properties.Count -lt 3)
        {
            Write-Warning "Event record missing expected fields. Skipping extended processing."
            $_ | Select-Object -Property TimeCreated, LogName, Id, Version, ProcessId, ThreadId, MachineName, UserId
            continue
        }

        $User = $_.Properties[0].Value
        $Domain = $_.Properties[1].Value
        $SourceIp = $_.Properties[2].Value

        $NormalizedUser = ("{1}\{0}" -f $User, $Domain)

        $Message = $_.Message.Split("`n")[0]

        $PropertyBag = @{
            TimeCreated = $_.TimeCreated;
            LogName = $_.LogName;
            Id = $_.Id;
            Version = $_.Version;
            ProcessId = $_.ProcessId;
            ThreadId = $_.ThreadId;
            MachineNae = $_.MachineName;
            UserId = $_.UserId;
            UserName = $NormalizedUser;
            SourceIp = $SourceIp;
            Message = $Message
        }

        $o = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $o
    } > "$FolderCreation\EventsLogs\RDP_Connections.txt"

}
Get-RdpConnectios

function Zip-Results {
   Write-Host "Running task 28 of 28" -ForegroundColor Yellow
   Write-Host "Write results to $FolderCreation.zip...`n"
   Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
   # Remove-Item -Path $FolderCreation -Recurse
}

Zip-Results

WriteLog -Level "INFO" Write-Host "===============================================================================`n" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "                              All tasks done                                   `n" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "                      Good luck in your investigation!!                        `n" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "`n"
WriteLog -Level "INFO" Write-Host "PowerTriage Github: https://github.com/jdangosto - Jesus Angosto (jdangosto)   `n" -ForegroundColor Yellow
WriteLog -Level "INFO" Write-Host "===============================================================================`n" -ForegroundColor Yellow