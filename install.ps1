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
