# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
function Get-ConfigParam {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string]$param,
        [string]$configParam,
        [string]$default=$null
    )
    if ([string]::IsNullOrEmpty($param)) {
        if (!([string]::IsNullOrEmpty($configParam))) {
            $configParam.trim()
        } else {
            If($null -ne $default) {
                $default.trim()
            } else { 
                $null
            }
        }
    } else {
        $param.trim()
    }
}
function Enable-RequiredWindowsFeatures {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $LogPath = "C:\Ed-Fi\Logs\install"
    )
    if (! $(Try { Test-Path $LogPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $LogPath
    }    
    $tooVerbose=Add-WindowsCapability -Online -Name OpenSSH.Client -LogPath "$LogPath\feature-openssh.txt"
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name NET-Framework-45-Core,NET-Framework-45-ASPNET -LogPath "$LogPath\feature-dotNet45FW.txt"
    Write-Verbose "$tooVerbose"
    $tooVerbose=Install-WindowsFeature -name Web-Server,Web-Common-Http,Web-Windows-Auth,Web-Basic-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter -IncludeManagementTools -LogPath "$LogPath\feature-iis.txt"
    Write-Verbose "$tooVerbose"
#    Install-WindowsFeature -name RSAT-AD-PowerShell
}
function Install-ChocolateyPackages {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $Packages,
        [string] $InstallPath = "C:\Ed-Fi",
        [string] $LogPath = "C:\Ed-Fi\Logs\install"
    )
    if ($null -eq $Packages) {
        Write-Verbose "Package list empty!"
        return
    }
    if (! $(Try { Test-Path $LogPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $LogPath
    }    
    if ($Packages -is [string]) {
        Write-Verbose "Installing simple (string) list of packages"
        Install-Choco -Packages $Packages -InstallPath $InstallPath -LogPath $LogPath -Verbose:$VerbosePreference
    }
    else {
        if ($Packages.Count -lt 1) {
            Write-Verbose "Package list empty!"
            return
        }
        $coreParams=@{InstallPath=$InstallPath;LogPath=$LogPath}
        $versionedPackages = $Packages | Where-Object {$null -ne $_.version}
        $arglistPackages = $Packages | Where-Object {($null -eq $_.version) -and (($null -ne $_.installargs) -or ($null -ne $_.packageparams))}
        $otherPackages = $Packages | Where-Object {($null -eq $_.version) -and ($null -eq $_.installargs) -and ($null -eq $_.packageparams)}
        $packageList = ""
        foreach ($pkgItem in $otherPackages) {
            $packageList+="$($pkgItem.package) "
        }
        Write-Verbose "Installing versioned packages first:"
        foreach ($pkgItem in $versionedPackages) {
            $pkgparams=@{Packages=$pkgItem.package; Version=$pkgItem.version;InstallArguments=$pkgItem.installargs;PackageParams=$pkgItem.packageparams}
            Install-Choco @pkgparams @coreParams -Verbose:$VerbosePreference
        }
        Write-Verbose "Arg or param list packages next:"
        foreach ($pkgItem in $arglistPackages) {
            $pkgparams=@{Packages=$pkgItem.package;InstallArguments=$pkgItem.installargs;PackageParams=$pkgItem.packageparams}
            Install-Choco @pkgparams @coreParams -Verbose:$VerbosePreference
        }
        if (![string]::IsNullOrEmpty($packageList)) {
            Write-Verbose "Installing remaining package list:"
            Install-Choco -Packages $packageList @coreParams -Verbose:$VerbosePreference    
        }
    }
}
function Install-Choco {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $Packages,
        [string] $Version,
        [string] $InstallArguments,
        [string] $PackageParams,
        [string] $Source,
        [string] $InstallPath = "C:\Ed-Fi",
        [string] $LogPath = "C:\Ed-Fi\Logs\install"
    )
    # Uses the Chocolatey package manager to install a list of packages
    # $packages is a space separated string of packages to install simultaneously with chocolatey
    #
    if (! $(Try { Test-Path $LogPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $LogPath
    }
    # Check/Install Chocolatey Package Manager 
    # 
    if (!(Get-Command "choco.exe" -ErrorAction SilentlyContinue)) {
        Write-Verbose "Installing Chocolatey package manager"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression -OutVariable logOut -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        Set-Content -Path "$LogPath\choco-install.txt" -Value $logOut
        # Start-Sleep -Seconds 2  # Yes..sigh..a 2 second pause
    }
    if (!(Get-Command "Update-SessionEnvironment" -ErrorAction SilentlyContinue)) {
        $env:ChocolateyInstall = Convert-Path "$((Get-Command choco).path)\..\.."
        Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
        refreshenv
    }
    $ChocoPath=(Get-Command "choco.exe" -ErrorAction SilentlyContinue).Source
    #
    # Attempt choco installs with versions or installargs and upgrades for the rest
    # 
    $logFile="$LogPath\"
    $chocArgs=[System.Collections.Generic.List[string]]::new()
    # These special cases will only work with one package at a time
    if ([string]::IsNullOrEmpty($PackageParams) -and [string]::IsNullOrEmpty($InstallArguments) -and [string]::IsNullOrEmpty($Version)) {
        $chocArgs.Add("upgrade")
        $chocArgs.Add($Packages)
        $logFile+="choco-upgrade-"
    }
    else {
        $chocArgs.Add("install")
        $chocArgs.Add($Packages)
        $logFile+="choco-install-"
        if ($PackageParams) {
            $chocArgs.Add("--params `"'$PackageParams'`"")
        }
        if ($InstallArguments) {
            $chocArgs.Add("--override --installarguments `"'$InstallArguments'`"")
        }
        if ($Version) {
            $chocArgs.Add("--version=$Version")
        }
        if ($Source) {
            $chocArgs.Add("--source=$Source")
        }
    }
    $pkgnames=$Packages -replace "\s","-"
    if ($pkgnames.Length -gt 20) {
        $logFile+=$pkgnames.Substring(0,19)
    }
    else {
        $logFile+=$pkgnames
    }
    $logFile+="-log.txt"
    $chocArgs.Add("-y")
    $chocArgs.Add("--log-file=$logFile")
    # Could use $chocArgs.ToArray()
    Write-Verbose "Start-Process -Wait -NoNewWindow -FilePath $ChocoPath -ArgumentList $chocArgs"
    Start-Process -Wait -NoNewWindow -FilePath $ChocoPath -ArgumentList $chocArgs
    Update-SessionEnvironment
}
function Copy-GitRepo {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $repoURL,
        [string] $InstallPath,
        [string] $keyPath
    )
    Write-Verbose "Cloning repo: $repoURL to $InstallPath"
    if (!(Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "git"
        if(!(Test-Path -ErrorAction SilentlyContinue "C:\Program Files\Git\cmd\git.exe")) {
            Write-Error "Error: Git not found on default installation path! Failed to clone repository!"
            return
        }
        else {
            $Env:Path += ";C:\Program Files\Git\cmd"
            if ($null -eq (Get-Command "git.exe" -ErrorAction SilentlyContinue)) {
                Write-Error "Error: Failed to find Git on path! Failed to clone repository!"
                return
            }
        }
    }
    $gitCmd=(Get-Command "git.exe").Source
    if (($null -eq $keyPath) -or [string]::IsNullOrEmpty($keyPath)) { 
        & $gitCmd clone $repoURL $InstallPath
    }
    else {
        $invertKeyPath=$keyPath.Replace('\','/')
        & $gitCmd clone $repoURL --config core.sshCommand="ssh -o StrictHostKeyChecking=no -i $invertKeyPath"
    }
}
function Copy-WebArchive {
    [CmdletBinding(DefaultParameterSetName='FilePathSet',HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [ValidateNotNullOrEmpty()][string]$Url,
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [ValidateNotNullOrEmpty()][string]$InstallPath,
        [Parameter(Mandatory=$true, ParameterSetName = 'FilePathSet')]
        [string]$FilePath,
        [Parameter(Mandatory=$true, ParameterSetName = 'DownloadPathSet')]
        [string]$DownloadsPath
    )
    if ($null -eq $FilePath) {
        if (! $(Try { Test-Path -ErrorAction SilentlyContinue $DownloadsPath } Catch { $false }) ) {
            $tooVerbose = New-Item -ItemType Directory -Force -Path $DownloadsPath
        }
        if ( $Url -match 'http.*\/(?<filename>[^/?]*)\??[^/]*' ){
            $FilePath="$DownloadsPath\$($matches["filename"])"
        }
        else {
            try {
                $fileRequest = [System.Net.WebRequest]::Create($Url)
                $fileRequest.AllowAutoRedirect=$false
                $fileResponse=$fileRequest.GetResponse()
                if ($fileResponse.StatusCode -eq "Found") {
                    $FilePath=[System.IO.Path]::GetFileName($fileResponse.GetResponseHeader("Location"))
                }
                else {
                    Write-Error "Unable to determine filename to store locally. Use -FilePath to specify."
                    return
                }
            }
            catch {
                Write-Error "Unable to determine filename to store locally. Use -FilePath to specify."
                return
            }
        }
    }
    if ($null -eq $FilePath) {
        throw "FilePath not set or unable to determine filename from URL."
    }
    if (Test-Path -ErrorAction SilentlyContinue $FilePath -PathType Container) {
        Write-Error "Folder at Path: $FilePath already exists! Canceling download and extract"
        return
    }
    else {
        if (Test-Path -ErrorAction SilentlyContinue $FilePath -PathType Leaf) {
            Write-Verbose "File exists, skipping download for Path: $FilePath."
        }
        else {
            try {
                $FileReq=Invoke-WebRequest -Uri $Url -OutFile $FilePath
                if ($FileReq.StatusCode -ge 400) {
                    Write-Error "Unable to download web archive from $Url to $FilePath. HTTP Status: $($FileReq.StatusDescription)Canceling download"
                    return
                }
            }
            catch {
                Write-Error "Unable to download web archive from $Url to $FilePath. Error: $_   Canceling download"
                return
            }
        }
    }
    if (Test-Path -ErrorAction SilentlyContinue $InstallPath -PathType Leaf) {
        Write-Verbose "Warning! Install Path not empty: $InstallPath `n Attempting to overwrite anyway."
        # Remove-Item $InstallPath -Recurse -Force
    }
    $tooVerbose=Expand-Archive -LiteralPath $FilePath -DestinationPath $InstallPath -Force
    Write-Verbose "Expand-Archive: $tooVerbose"
}
function Copy-WebFile {
    [CmdletBinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$Url,
        [ValidateNotNullOrEmpty()][string]$FilePath,
        [switch]$Overwrite
    )
    if ((Test-Path -ErrorAction SilentlyContinue $FilePath -PathType Leaf) -and (!$Overwrite)) {
        Write-Verbose "File exists at Path: $FilePath."
    }
    else {
        try {
            $FileReq=Invoke-WebRequest -Uri $Url -OutFile $FilePath
            if ($FileReq.StatusCode -ge 400) {
                Write-Error "Unable to download web file from $Url to $FilePath. HTTP Status: $($FileReq.StatusDescription) `n Canceling download"
                return
            }
        }
        catch {
            Write-Error "Unable to download web file from $Url to $FilePath. Error: $_ `n Canceling download"
            return
        }
    }
}
function Convert-HashtableToString {
    param (
        [Parameter(Mandatory = $true)][System.Collections.Hashtable] $Hashtable
    )
    $buildString = "@{"
    foreach ($key in $Hashtable.keys) {
        $val = $Hashtable[$key]
        if ($key -match "\s") {
            $buildString += "`"$key`"" + "=" + "`"$val`"" + ";"
        }
        else {
            $buildString += $key + "=" + "`"$val`"" + ";"
        }
    }
    $buildString += "}"
    return $buildString
}
function Install-NugetPackage {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $packageName,
        [string] $version,
        [string] $packageSource = "https://www.myget.org/F/ed-fi/",
        [string] $FilePath = "C:\Ed-Fi\Downloads",
        [string] $LogPath = "C:\Ed-Fi\Logs\install"
    )
    # Verify that the Downloads folder is present
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }
    if (! $(Try { Test-Path $LogPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $LogPath
    }    
    $downloadedPackagePath = Join-Path $FilePath "$packageName.$version"
    if (!(Get-Command "nuget.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "nuget.commandline"
        if(!(Test-Path -ErrorAction SilentlyContinue "C:\ProgramData\chocolatey\bin\nuget.exe")) {
            return "Error: Git not installed!"
        }
        else {
            $Env:Path += ";C:\ProgramData\chocolatey\bin"
            if ($null -eq (Get-Command "nuget.exe" -ErrorAction SilentlyContinue)) {
                return "Error: Failed to install Nuget"
            }
        }
    }
    $nugetPath=$(Get-Command "nuget.exe").Source
    $nugetCMD=Start-Process -Wait -FilePath $nugetPath -NoNewWindow -ArgumentList "install $packageName","-source $packageSource","-Version $version","-outputDirectory $FilePath","-NoCache" -RedirectStandardOutput "$LogPath\nuget_$($version)_log.txt" -RedirectStandardError "$LogPath\nuget_$($version)_err.txt"
    if ($nugetCMD.ExitCode -ne 0) {
        throw "Failed to install package $packageName $version"
    }
    return $downloadedPackagePath
}
