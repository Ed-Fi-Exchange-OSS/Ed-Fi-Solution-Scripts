# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
#Requires -Version 5
#Requires -RunAsAdministrator
param (
    $DnsName,
    $AdminEmail,
    $DDNSUrl,
    $DDNSUsername,
    $DDNSPassword,
    $SolutionName,
    $InstallType="Demo"
)
    <#
    .description
    A simple launcher for the solution installer.  Gets a basic working environment of Chocolatey and Git installed.
    .parameter SolutionName
    A list of solution names, an empty string for all solutions, or "base" to install only a current Ed-Fi Suite
    .parameter InstallType
    The type of deployment to install: 'Demo' or 'Staging'
    .parameter AdminEmail
    An email address of the administrative contact.
    .parameter DnsName
    The DNS name chosen for this environment, or blank to use only localhost and self-signed certificates.
    .parameter DDNSUrl
    A provider URL for posting dynamic DNS updates from this system.
    .parameter DDNSUsername
    The Username required to authenticate with dynamic DNS provider.
    .PARAMETER DDNSPassword
    The Username required to authenticate with dynamic DNS provider.

    .EXAMPLE
    install.ps1 -DnsName "my.domain.org" -AdminEmail "admin@domain.org" -DDNSUrl "https://dynamicdns.com?name={DnsName}&ip={IP}" -DDNSUsername name -DDNSPassword "pass" -SolutionName <see solution config for list of names> -InstallDemo "Demo|Staging"
    #>

function Install-ChocoGitPkg {
    Set-ExecutionPolicy Bypass -Scope Process -Force;[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    $ChocoCmd=Get-Command "choco.exe" -ErrorAction SilentlyContinue
    $ChocolateyInstall = Convert-Path "$($ChocoCmd.Path)\..\.."
    Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    refreshenv
    Start-Process -Wait -NoNewWindow -FilePath $ChocoCmd.Source -ArgumentList "upgrade git","-y","--no-progress"
    Update-SessionEnvironment
}
$EdFiDir="C:\Ed-Fi"
$ScriptDir="$EdFiDir\install"
$repoURL="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts"
New-Item -ItemType directory -Path $EdFiDir -ErrorAction SilentlyContinue
Set-Location $EdFiDir
Start-Transcript -Path "$EdFiDir\install.log"
Install-ChocoGitPkg
$gitCmd=(Get-Command "git.exe").Source
Start-Process -Wait -NoNewWindow -FilePath $gitCmd -ArgumentList "clone $repoURL $ScriptDir"
Set-Location $ScriptDir
$installParams=@{
    'Verbose'=$true
    'InstallType' = $InstallType
}
if (!([string]::IsNullOrEmpty($DnsName))) {
    $installParams['DnsName']=$DnsName
}
if (!([string]::IsNullOrEmpty($AdminEmail))) {
    $installParams['AdminEmail']=$AdminEmail
}
if (!([string]::IsNullOrEmpty($DDNSUrl))) {
    $installParams['DDNSUrl']=$DDNSUrl
}
if (!([string]::IsNullOrEmpty($DDNSUsername))) {
    $installParams['DDNSUsername']=$DDNSUsername
}
if (!([string]::IsNullOrEmpty($DDNSPassword))) {
    $installParams['DDNSPassword']=$DDNSPassword
}
if (!([string]::IsNullOrEmpty($SolutionName))) {
    $installParams['SolutionName']=$SolutionName
}
Stop-Transcript
& $ScriptDir\install_solution.ps1 @installParams
