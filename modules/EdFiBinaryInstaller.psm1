# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.

[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
if (!(Get-Command "Install-Choco" -ErrorAction SilentlyContinue)) {
    Import-Module EdFiSolutionInstaller.psm1 # Need thus module too
}
Function Install-BaseEdFi {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $InstallType,       # $InstallType can be "Staging", "Demo", or "Sandbox"
        $SuiteVersion,      # $SuiteVersion includes minor revision numbers for now e.g. "3.4.0" or "2.6.0" but will change with semantic versioning
        $DnsName="localhost",
        $EdFiDir="C:\Ed-Fi",
        $iisConfig=@{ iisUser="IIS_IUSRS"; SiteName="Default Web Site"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $binariesConfigFile="$PSScriptRoot\binaries.ps1"
    if (!(Test-Path $binariesConfigFile)) {
        $binariesConfigFile="$PSScriptRoot\modules\binaries.ps1"
        if (!(Test-Path $binariesConfigFile)) {
            throw "Error loading binaries config package"
        }
    }
    $versionNum = 'v'+$SuiteVersion.Replace(".", "")
    $directories = @{
        dbPath = "$EdFiDir\dbs";
        download = "$EdFiDir\downloads";
        install = "$EdFiDir\v$SuiteVersion-$InstallType";
        appLog = "$EdFiDir\logs"
    }
    $dirPermissions = @{
        dbPath = @{ 
            iis="NoAccess";
            userPerms="" };
        download = @{ 
            iisPerms="Modify";
            userPerms="Modify" };
        install = @{ 
            iisPerms="ReadAndExecute";
            userPerms="" };
        appLog = @{ 
            iisPerms="Modify";
            userPerms="ReadAndExecute" }
    }
    # IIS settings
    $virtualDirectoryName = "$versionNum-$InstallType"
    $appsBaseUrl = "https://$DnsName/$virtualDirectoryName"
    $apiBaseUrl = "$appsBaseUrl/api"
    # Database vars
    $backupLocation = "$EdFiDir\v$SuiteVersion-$InstallType\dbs"
    $NamePrefix = "$InstallType"
    $NameSuffix = "$($InstallType)_$versionNum"
    $logFileSuffix = "$($InstallType)-$($versionNum)"
    $odsName="" # Will add prefix and suffix so ODS name could be: Staging_EdFiODS_v340
    # 1. Ensure paths exist and set permissions accordingly
    if (! $(Try { Test-Path $EdFiDir -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $EdFiDir
    }
    # TODO: Give Users group Modify access to avoid any problems, just this folder. This might need to be adjusted with a new group.
    Set-PermissionsOnPath $EdFiDir "Users" "Modify" "ObjectInherit"
    # TODO: Give execute access to main dir without inheritance to containers, might want to lock down better.
    Set-PermissionsOnPath $EdFiDir $iisConfig.iisUser "Traverse"
    #
    foreach ($dirkey in $directories.Keys) {
        Add-AppDirectory -iisUser $iisConfig.iisUser -dirPath $directories[$dirkey] -iisPerms $dirPermissions[$dirkey].iisPerms -userPerms $dirPermissions[$dirkey].userPerms
    }
    #
    $appLogPath = $directories.appLog
    # Binaries Metadata
    $binaries = Invoke-Expression (Get-Content -Raw -Path $binariesConfigFile)
    #
    # 2. Add main virtual directory for this Ed-Fi Suite to IIS
    if ($virtualDir=Get-WebVirtualDirectory -Site $iisConfig.SiteName -Name $virtualDirectoryName -ErrorAction SilentlyContinue ) {
        Write-Verbose "Virtual directory for Suite: $SuiteVersion found at: $virtualDir `n  Skipping re-installation for site: $($iisConfig.SiteName)"
    } else {
        $virtualDir=New-WebVirtualDirectory -Site $iisConfig.SiteName -Name $virtualDirectoryName -PhysicalPath $directories.install -Force
        Write-Verbose "New-WebVirtualDirectory: $virtualDir"
    }
    # Create a list to collect the URLs for later use
    $appUrlList = [System.Collections.Generic.List[System.Collections.Hashtable]]::new()
    #
    # 3. Download, extract/install, and set permissions for all listed binaries
    #
    foreach ($b in $binaries | Where-Object {($_.requiredInInstallTypes.Contains($InstallType)) -or (!$_.requiredInInstallTypes)}) {
        # Concatenate path for binary from name and dl location.
        # Note: all NuGet packages are zips.
        $dlFilePath = "$($directories.download)\$($b.name)$SuiteVersion.zip"
        $pkgInstallPath = "$($directories.install)\$($b.name)"
        $downloadUrl = $b.url
        if($b.urlVersionOverride -and $b.urlVersionOverride[$versionNum]){ $downloadUrl = $b.urlVersionOverride[$versionNum] }
        try {
            Copy-WebArchive -Url $downloadUrl -InstallPath $pkgInstallPath -FilePath $dlFilePath
        }
        catch {
            Write-Warning "Binary $($b.name) was not installed. Message: $_"
        }
        $AccessPermissions="ReadAndExecute"
        if ($b.name -eq "AdminApp") { $AccessPermissions="Modify" }
        Set-PermissionsOnPath $pkgInstallPath $iisConfig.iisUser $AccessPermissions
    }
    # 4. Loop back over webapps and add them to IIS, then update Web.config values AppSettings, ConnStrings and Log Files
    foreach ($b in $binaries | Where-Object {($_.type -eq "WebApp") -and (($_.requiredInInstallTypes.Contains($InstallType)) -or (!$_.requiredInInstallTypes))}) {
        $appName = $b.name
        $appPhysicalPath = "$($directories.install)\$appName"
        $applicationIISPath = "$($iisConfig.SiteName)/$virtualDirectoryName/$appName"
        if ($webAppInstall=Get-WebApplication -Name $appName  -Site "$($iisConfig.SiteName)\$virtualDirectoryName" -ErrorAction SilentlyContinue) {
            Write-Verbose "Web app: $appName is already installed: $webAppInstall"
            continue
        }
        else {
            $webAppInstall=New-WebApplication -Name $appName  -Site "$($iisConfig.SiteName)\$virtualDirectoryName" -PhysicalPath $appPhysicalPath -ApplicationPool $($iisConfig.applicationPool) -Force
            Write-Verbose "New-WebApplication: $webAppInstall"
        }
        # Add URL of app to table
        if ($b.name -ne "Api") {
            $appUrlList.Add(@{ name="Ed-Fi $($b.name) $virtualDirectoryName"; type="URL"; URI="/$virtualDirectoryName/$($b.name)"})
        }
        else {
            if ($versionNum -ne "v260") {
                $appUrlList.Add(@{ name= "Ed-Fi API $virtualDirectoryName"; type= "URL"; URI="/$virtualDirectoryName/api" })
            } else {
                $appUrlList.Add(@{ name="Copy this URL for configuring Ed-Fi v2.6 API clients"; type="URL"; URI="/$virtualDirectoryName/api"})
            }
        }
        # Set IIS Authentication settings
        if($b.iisAuthentication) {
            foreach($key in $b.iisAuthentication.Keys) {
                Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$key" -Name Enabled -Value $b.iisAuthentication.Item($key) -PSPath IIS:\ -Location "$applicationIISPath"
                if (($key -like "windowsAuthentication") -and ($b.iisAuthentication.Item($key))) {
#                    Set-WebConfigurationProperty  -PSPath IIS:\ -location "$applicationIISPath" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking" -value "Allow"
                    Add-WebConfigurationProperty  -PSPath IIS:\ -location "$applicationIISPath" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "." -value @{name="HTTP/$DnsName"}
                }
            }
        }
        #
        $appPhysicalPath = "$appPhysicalPath\Web.Config"
        # Apply global settings
        if($b.appSettings)       { Set-AppSettingsInWebConfig $appPhysicalPath $b.appSettings }
        if($b.connectionStrings) { Set-ConnectionStringsInWebConfig $appPhysicalPath $b.connectionStrings}
        if($b.logFile)           { Set-Log4NetLogFileInWebConfig $appPhysicalPath $b.logFile}
        if($b.webConfigTagInsert){ Set-TagInWebConfig $appPhysicalPath $b.webConfigTagInsert}

        # InstallType and Version Specifics
        if($b.envAppSettings) {
            if($b.envAppSettings[$versionNum][$InstallType]){ 
                Set-AppSettingsInWebConfig $appPhysicalPath $b.envAppSettings[$versionNum][$InstallType] 
            } else {
                Set-AppSettingsInWebConfig $appPhysicalPath $b.envAppSettings[$versionNum]
            }
        }
        if($b.envConnectionStrings -and $b.envConnectionStrings[$InstallType]) { 
            $connStringTable = $b.envConnectionStrings[$InstallType]
            Set-ConnectionStringsInWebConfig $appPhysicalPath $connStringTable 
            if ($connStringTable["EdFi_Ods"]) {
                $odsName = $connStringTable["EdFi_Ods"]
            }
        }
        # v2.x
        if($versionNum -eq "v260") { 
            if($b.name -eq "AdminApp") {
                $secretJsonPhysicalPath = "$($directories.install)\$($b.name)\secret.json"
                Set-IntegratedSecurityInSecretJsonFile($secretJsonPhysicalPath)
            }

            if($b.name -eq "Docs") {
                $swaggerDefaultHtmlPath = "$($directories.install)\$($b.name)\default.html"
                Set-DocsHTMLPathsToWorkWithVirtualDirectories($swaggerDefaultHtmlPath)
            }
        }
    }
    # 5. Restore downloaded databases
    $apiDatabases = ($binaries | Where-Object {$_.name -eq "Api"}).databases;
    foreach($db in $apiDatabases | Where-Object {($_.InstallType -eq $InstallType) -or (!$_.InstallType)}) {
        $dbBackupFile = "$backupLocation\$($db.src).bak"
        try {
            Restore-Database $db.src $db.dest $dbBackupFile $directories.dbPath
        }
        catch {
            Write-Warning "Database restore failed. Message: $_"
        }
    }

    # 6. Install Analytics Middle Tier to ODS table, won't have much effect on a Sandbox env but should still work
    if ($odsName -ne "") {
        Install-AMT $EdFiDir $SuiteVersion $odsName
    }
    
    # 7. Add URLs for all Apps to desktop
    if (!(Get-Command "Add-DesktopAppLinks" -ErrorAction SilentlyContinue)) {
        Import-Module .\EdFiBinaryInstaller.psm1
    }
    Add-DesktopAppLinks $appUrlList -Verbose:$VerbosePreference
    Add-WebAppLinks -AppURIs $appUrlList -DnsName $DnsName -SolutionName "Ed-Fi Tools for ODS/API v$SuiteVersion" -Verbose:$VerbosePreference # -EdFiWebDir $SolutionWebRoot

}
# Region: Web.Config Functions
function Add-AppDirectory {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $iisUser,
        $dirPath,
        $iisPerms,
        $userPerms
    )
    Write-Verbose "  Add-AppDirectory -iisUser $iisUser -dirPath $dirPath -iisPerms $iisPerms -userPerms $userPerms"
    # Such as dirPath="$EdFiDir\item", iisPerms="NoAccess", userPerms="Modify"
    if (! $(Try { Test-Path $dirPath -ErrorAction SilentlyContinue } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $dirPath
    }
    if (![string]::IsNullOrEmpty($iisPerms)) {
        Set-PermissionsOnPath $dirPath $iisUser $iisPerms -Verbose:$VerbosePreference # TODO: Review security
    }
    if (![string]::IsNullOrEmpty($userPerms)) {
        Set-PermissionsOnPath $dirPath "Users" $userPerms -Verbose:$VerbosePreference # TODO: Review security
    }
}
# dictionary in this case is a Hash with @{"xPath" = "Value"}
# for example: @{"//initialization" = "<users>....</users>"}
Function Set-TagInWebConfig($webConfigPath, $dictionary)
{
    # Load XML File and Content
    $xml = [xml](Get-Content $webConfigPath)

    foreach($key in $dictionary.Keys)
    {
        # Select the xPath Node
        $xmlNode = $xml.SelectSingleNode($key)

        # Update content.
        $xmlNode.SetAttribute('enabled',$true)
        $xmlNode.RemoveAttribute('configSource')
        $xmlNode.InnerXML = $dictionary[$key]
    }

    #Once done save.
    $xml.Save($webConfigPath)
}
Function Set-AttributeValueInWebConfig($webConfigPath, $xPath, $attribute, $value)
{
    $xml = [xml](Get-Content $webConfigPath)

    # Use XPath to find the appropriate node
    if(($node = $xml.SelectSingleNode($xPath)))
    {
        $node.SetAttribute($attribute,$value)
    }

    $xml.Save($webConfigPath)
}
Function Set-AppSettingsInWebConfig($webConfigPath, $dictionary)
{
    $xml = [xml](Get-Content $webConfigPath)

    foreach($key in $dictionary.Keys)
    {
        # Use XPath to find the appropriate node
        if(($addKey = $xml.SelectSingleNode("//appSettings/add[@key = '$key']")))
        {
            $addKey.SetAttribute('value',$dictionary[$key])
        }
    }

    $xml.Save($webConfigPath)
}
Function Set-ConnectionStringsInWebConfig($webConfigPath, $connectionStrings)
{
    $xml = [xml](Get-Content $webConfigPath)

    foreach($key in $connectionStrings.Keys)
    {
        # Use XPath to find the appropriate node
        if(($addKey = $xml.SelectSingleNode("//connectionStrings/add[@name = '$key']")))
        {
            $addKey.SetAttribute('connectionString',$connectionStrings[$key])
        }
    }

    $xml.Save($webConfigPath)
}
Function Set-Log4NetLogFileInWebConfig($webConfigPath, $logFile)
{
    $xml = [xml](Get-Content $webConfigPath)

    foreach($key in $logFile.Keys)
    {
        # Use XPath to find the appropriate node
        if(($addKey = $xml.SelectSingleNode("//log4net/appender/file")))
        {
            $addKey.SetAttribute('value',$logFile[$key])
        }
    }

    $xml.Save($webConfigPath)
}
#TODO: Make this function more generic. Function Set-ValuesInJsonFile($jsonFilePath, $dictionary)
Function Set-IntegratedSecurityInSecretJsonFile($jsonFilePath) {
    $a = Get-Content $jsonFilePath -raw | ConvertFrom-Json

    $a.update | ForEach-Object {$a.AdminCredentials.UseIntegratedSecurity = "true"}
    
    $a | ConvertTo-Json -depth 32| set-content $jsonFilePath
}
# endregion

# Region: MsSQL Database Functions
Function Restore-Database {
    param (
        $dbSource, 
        $dbDestinationName, 
        $dbBackupPath, 
        $dbPath,
        $SQLServerName="."
        )
    $server = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
    if ($null -eq $dbPath) {
        $dataFilePath = $(if ($server.Settings.DefaultFile) {$server.Settings.DefaultFile} else {$server.Information.MasterDBPath})
        $logFilePath = $(if ($server.Settings.DefaultLog) {$server.Settings.DefaultLog} else {$server.Information.MasterDBLogPath})
    }
    else {
        $dataFilePath=$dbPath
        $logFilePath=$dbPath
    }
    $dbRestorePath = "$dataFilePath\$dbDestinationName.mdf"
    $logRestorePath = "$logFilePath\$dbDestinationName.ldf"
    if ($(Try { Test-Path $dbRestorePath -ErrorAction SilentlyContinue } Catch { $false })) {
        throw "Database: $dbDestinationName already exists at: $dbRestorePath"
    }
    Write-Verbose "Restore database $dbSource as $dbDestinationName from file $dbBackupPath to $dbRestorePath with log $logRestorePath"

    $backupDeviceItem = New-Object Microsoft.SqlServer.Management.Smo.BackupDeviceItem -ArgumentList $dbBackupPath,'File'
    $restore = New-Object Microsoft.SqlServer.Management.Smo.Restore
    $restore.Database = $dbDestinationName
    $tooVerbose = $restore.Devices.Add($backupDeviceItem)
    $backupFiles = $restore.ReadFileList($server)

    foreach ($file in $backupFiles) {
        $relocateFile = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile
        $relocateFile.LogicalFileName = $file.LogicalName
        if ($file.Type -eq 'D') {
            $relocateFile.PhysicalFileName = $dbRestorePath
        }
        else {
            $relocateFile.PhysicalFileName = $logRestorePath
        }
        $tooVerbose = $restore.RelocateFiles.Add($relocateFile) 
    }
    try {
        $tooVerbose = $restore.SqlRestore($server)
    }
    catch {
        Write-Error " Unable to restore core database from backup.`n   Exception: $($_.Exception) Details: $_"
    }
    Write-Verbose "Restore of database completed:`n  $tooVerbose"
}
# endregion
Function Initialize-Url($url){
        
        $HttpReq = [System.Net.HttpWebRequest]::Create($url)
        $HttpReq.Timeout = 600 * 1000
        
        try { $HttpReq.GetResponse() }
        catch [System.Net.WebException] {
            if ($_.Exception.status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
                Write-Error "SSL validation error: $_"
            }
            elseif ($ignoreInternalServerErrors) {
                Write-Verbose "Caught and ignored an internal server error"
            }
            else {
                Write-Error "Non-SSL server error, verify server is running correctly: $_"
            }
        }
}
Function Set-DocsHTMLPathsToWorkWithVirtualDirectories($swaggerDefaultHtmlPath)
{
    $fileContent = Get-Content $swaggerDefaultHtmlPath
    $fileContent[3]+="<base href='docs/' />"
    $fileContent | Set-Content $swaggerDefaultHtmlPath
}
function Install-AMT($EdFiDir="C:\Ed-Fi",$ODSVersion,$dbConnectionStr) {
    Write-Verbose "Installing Analytics Middle Tier for Ed-Fi ODS v$ODSVersion"
    if (! $(Try { Test-Path "$EdFIDir\AMT" } Catch { $false }) ) {
        Set-Location $EdFiDir
        $repoURL="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-Analytics-Middle-Tier.git"
        Copy-GitRepo $repoURL "$EdFIDir\AMT"
    }
    if ($null -eq (Get-Command "dotnet.exe" -ErrorAction SilentlyContinue)) {
        Install-Choco "dotnetcore-sdk"
        if ($(Try { Test-Path "C:\Program Files\dotnet\dotnet.exe" } Catch { $false })) {
            $Env:Path += ";C:\Program Files\dotnet"
        }
        else {
            Write-Error "Unable to install Analytics Middle Tier because dotnet.exe is not found"
            return
        }
    }
    $dotnetCmd=(Get-Command "dotnet.exe").Source
    $installOptions = "Indexes"
    Set-Location "$EdFiDir\AMT\src"
    & $dotnetCmd build
    Set-Location "$EdFiDir\AMT\src\EdFi.AnalyticsMiddleTier.Console"
    & $dotnetCmd run --connectionString $dbConnectionStr --options $installOptions
    Set-Location $EdFiDir
}
function Install-DataImport($EdFiDir="C:\Ed-Fi",$GitPrefix) {
    Write-Verbose "Installing Data Import"
    if (! $(Try { Test-Path "$EdFIDir\DataImport" } Catch { $false }) ) {
        Write-Host "Please download the Data Import ZIP file from: https://techdocs.ed-fi.org/download/attachments/64685133/EdFi.DataImport.Installation.1.0.1.zip?version=1&modificationDate=1576113640540&api=v2 and extract to $EdFiDir\DataImport"
        Write-Host "Or download and run the installer if you haven't already: https://techdocs.ed-fi.org/download/attachments/64685133/EdFi.DataImport.Installation.1.0.1.zip?version=1&modificationDate=1576113640540&api=v2"
        return
    }
    Set-Location "$EdFiDir\DataImport"
    $repoURL="https://$GitPrefix@github.com/Ed-Fi-Alliance/Ed-Fi-DataImport"
    Copy-GitRepo $repoURL "$EdFIDir\DataImport"
    Write-Verbose "Misssing binary installer for Data Import"
}