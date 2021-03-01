# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.

if (!(Get-Command "Install-Choco" -ErrorAction SilentlyContinue)) {
    Import-Module EdFiSolutionInstaller.psm1 # Need thus module and all of its dependencies too
}
Function Install-BaseEdFi {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $InstallType,       # $InstallType can be "Staging", "Demo", or "Sandbox"
        $SuiteVersion,      # $SuiteVersion includes minor revision numbers for now e.g. "3.4.0" or "2.6.0" but will change with semantic versioning
        $DnsName="localhost",
        $EdFiDir="C:\Ed-Fi",
        $iisConfig=@{ iisUser="IIS_IUSRS"; SiteName="Ed-Fi"; applicationPool = "EdFiAppPool"; integratedSecurityUser = "IIS APPPOOL\EdFiAppPool"; defaultIntegratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $binariesConfigFile="$PSScriptRoot\binaries-v5.ps1"
    if (!(Test-Path $binariesConfigFile)) {
        $binariesConfigFile="$PSScriptRoot\modules\binaries.ps1"
        if (!(Test-Path $binariesConfigFile)) {
            throw "Error loading binaries config package"
        }
    }
    $versionNum = 'v'+$SuiteVersion.Replace(".", "")
    $binaryPackage="$versionNum-$InstallType"
    $NamePrefix = "$InstallType"
    $NameSuffix = "$($InstallType)_$versionNum"
    $logFileSuffix = "$($InstallType)-$($versionNum)"
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
    $OdsApiParams = @{Api="$appsBaseUrl/api"}
    # Database vars
    # $backupLocation = "$EdFiDir\v$SuiteVersion-$InstallType\dbs"
    # $odsName="" # Will add prefix and suffix so ODS name could be: Staging_EdFiODS_v340
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
    $myBinary = $binaries | Where-Object {$_.name -like $binaryPackage}
    if ($null -eq $myBinary) {
        throw "Unable to find binary download package information for $binaryPackage"
    }
    #
    # 2. Add main virtual directory for Ed-Fi Suite to IIS
    if ($virtualDir=Get-WebVirtualDirectory -Site $iisConfig.SiteName -Name $virtualDirectoryName -ErrorAction SilentlyContinue ) {
        Write-Verbose "Virtual directory for Suite: $SuiteVersion found at: $virtualDir `n  Skipping re-installation for site: $($iisConfig.SiteName)"
    } else {
        $virtualDir=New-WebVirtualDirectory -Site $iisConfig.SiteName -Name $virtualDirectoryName -PhysicalPath $directories.install -Force
        Write-Verbose "New-WebVirtualDirectory: $virtualDir"
    }
    # Create a list to collect the URLs for later use
    $appUrlList = [System.Collections.Generic.List[System.Collections.Hashtable]]::new()
    #
    # 3. Download, extract/install, and set permissions for all listed archive files
    #
    $archiveList=$myBinary.archives
    foreach ($arc in $archiveList) {
        $dlFilePath="$($directories.download)\$($arc.filename)"
        if ($arc.type -like "webapp") {
            try {
                $appInstallPath="$($directories.install)\$($arc.name)"
                Copy-WebArchive -Url $arc.archive -InstallPath $appInstallPath -FilePath $dlFilePath
                $AccessPermissions="ReadAndExecute"
                if ($arc.name -like "AdminApp") { $AccessPermissions="Modify" }
                Set-PermissionsOnPath $appInstallPath $iisConfig.iisUser $AccessPermissions
                $applicationIISPath = "$($iisConfig.SiteName)/$virtualDirectoryName/$($arc.name)"
                if ($webAppInstall=Get-WebApplication -Name $arc.name  -Site "$($iisConfig.SiteName)\$virtualDirectoryName" -ErrorAction SilentlyContinue) {
                    Write-Verbose "Web app: $appName is already installed: $webAppInstall"
                }
                else {
                    $webAppInstall=New-WebApplication -Name $appName  -Site "$($iisConfig.SiteName)\$virtualDirectoryName" -PhysicalPath $appPhysicalPath -ApplicationPool $($iisConfig.applicationPool) -Force
                    Write-Verbose "New-WebApplication: $webAppInstall"
                    $applicationIISPath = "$($iisConfig.SiteName)/$virtualDirectoryName/$($app.name)"
                    $configSection=$app.config
                    Set-AppConfigSettings -AppName $app.name -Config $configSection -PhysicalPath $appPhysicalPath -WebPath  $applicationIISPath -iisConfig $iisConfig
                    $appUrlList.Add(@{ name="Ed-Fi $($b.name) $virtualDirectoryName"; type="URL"; URI="/$virtualDirectoryName/$($b.name)"})
                }
            }
            catch {
                Write-Warning "Web app $($arc.name) was not installed. Message: $_"
            }
        }
        elseif ($arc.type -like "mssql") {
            try {
                Copy-WebFile -Url $arc.archive -FilePath $dlFilePath
                Restore-MSSQLDatabase -dbBackupPath $dlFilePath -dbDestinationName $arc.name -dbDestinationPath $directories.dbPath
                if ($arc.name -like "EdFi-Ods") { 
                    $odsName = $arc.name
                    $OdsApiParams.Add("Ods","$odsName")
                }
            }
            catch {
                Write-Warning "Database $($arc.name) was not restored. Message: $_"
            }
        }
    }

    # Install Analytics Middle Tier for ODS
    if ($odsName -ne "") {
        Install-AMT $EdFiDir $SuiteVersion $odsName
    }
    
    # Add URLs for all Apps
    $OdsApiParams.Add("Urls",$appUrlList)
    return $OdsApiParams
}
function Add-AppDirectory {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $iisUser,
        $dirPath,
        $iisPerms,
        $userPerms
    )
    Write-Verbose " Add-AppDirectory -iisUser $iisUser -dirPath $dirPath -iisPerms $iisPerms -userPerms $userPerms"
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
function Set-AppConfigSettings {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $AppName,
        $configSections,
        $PhysicalPath,
        $WebPath,
        $iisConfig
        )
            # Set IIS Authentication settings
            if($configSection.iisAuthentication) {
                foreach($key in $configSection.iisAuthentication.Keys) {
                    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$key" -Name Enabled -Value $configSection.iisAuthentication.Item($key) -PSPath IIS:\ -Location "$applicationIISPath"
                }
            }
            #
            $appPhysicalPath = "$appPhysicalPath\Web.Config"
            # Apply global settings
            if($configSection.appSettings)       { Set-AppSettingsInWebConfig $appPhysicalPath $configSection.appSettings }
            if($configSection.connectionStrings) { Set-ConnectionStringsInWebConfig $appPhysicalPath $configSection.connectionStrings}
            if($configSection.logFile)           { Set-Log4NetLogFileInWebConfig $appPhysicalPath $configSection.logFile}
            if($configSection.webConfigTagInsert){ Set-TagInWebConfig $appPhysicalPath $configSection.webConfigTagInsert}
    
            # InstallType and Version Specifics
            if($configSection.envAppSettings) {
                if($configSection.envAppSettings[$versionNum][$InstallType]){ 
                    Set-AppSettingsInWebConfig $appPhysicalPath $configSection.envAppSettings[$versionNum][$InstallType] 
                } else {
                    Set-AppSettingsInWebConfig $appPhysicalPath $configSection.envAppSettings[$versionNum]
                }
            }
            if($configSection.envConnectionStrings -and $configSection.envConnectionStrings[$InstallType]) { 
                $connStringTable = $configSection.envConnectionStrings[$InstallType]
                Set-ConnectionStringsInWebConfig $appPhysicalPath $connStringTable 
                if ($connStringTable["EdFi_Ods"]) {
                    $odsName = $connStringTable["EdFi_Ods"]
                }
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
    if (! $(Try { Test-Path "$EdFIDir\DataImport" } Catch { $false }) ) {
        Write-Host "Please download the Data Import ZIP file from: https://techdocs.ed-fi.org/download/attachments/64685133/EdFi.DataImport.Installation.1.0.1.zip?version=1&modificationDate=1576113640540&api=v2 and extract to $EdFiDir\DataImport"
        Write-Host "Or download and run the installer if you haven't already: https://techdocs.ed-fi.org/download/attachments/64685133/EdFi.DataImport.Installation.1.0.1.zip?version=1&modificationDate=1576113640540&api=v2"
        return
    }
    Set-Location "$EdFiDir\DataImport"
    $repoURL="https://$GitPrefix@github.com/Ed-Fi-Alliance/Ed-Fi-DataImport"
    Copy-GitRepo $repoURL "$EdFIDir\DataImport"
}