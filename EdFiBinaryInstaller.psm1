# Largely stolen from Douglas Loyo, Sr. Solutions Architect @ MSDF
# load assemblies
# Need SmoExtended for backups
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
if (!(Get-Command "Install-Choco" -ErrorAction SilentlyContinue)) {
    Import-Module EdFiSolutionInstaller.psm1 # Need thus module too
}
Function Install-BaseEdFi {
    [cmdletbinding(HelpUri="https://github.com/skerlick-edfi/Ed-Fi-Solution-Scripts")]
    param (
        $InstallType,       # $InstallType can be "Production", "Staging", or "Sandbox"
        $SuiteVersion,      # $SuiteVersion includes minor revision numbers for now e.g. "3.4.0" or "2.6.0" but will change with semantic versioning
        $DnsName,
        $EdFiDir="C:\Ed-Fi",
        $iisConfig=@{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; applicationPool = "DefaultAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $versionNum = 'v'+$SuiteVersion.Replace(".", "")
    $dataFilePath = "$EdFiDir\dbs"
    $logFilePath  = "$EdFiDir\dbs"
    $downloadPath = "$EdFiDir\downloads"
    $installPath = "$EdFiDir\v$SuiteVersion-$InstallType" # $installPath = "C:\inetpub\wwwroot\v$SuiteVersion$InstallType"
    $appLogPath="$EdFiDir\logs"
    # IIS settings
    $virtualDirectoryName = "$versionNum-$InstallType"
#    $appsBaseUrl = "https://$DnsName/$virtualDirectoryName"
    $appsBaseUrl = "https://localhost/$virtualDirectoryName"
    $apiBaseUrl = "$appsBaseUrl/api"
    # Database vars
    $backupLocation = "$installPath\dbs"
    $dbNamePrefix = "$InstallType"
    $dbNameSufix = "$versionNum"
    $logFileSuffix = "$($versionNum)-$($InstallType)"
    $odsName="" # Will add prefix and suffix so ODS name could be: Production_EdFiODS_v340
    # 1. Ensure paths exist and set permissions accordingly
    if (! $(Try { Test-Path $EdFiDir } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $EdFiDir 
    }
    Set-PermissionsOnPath $EdFiDir "Users" "Modify"  # TODO: Give Users group Modify access to avoid any problems. This might need to be adjusted with a new group.
    Set-PermissionsOnPath $EdFiDir $iisConfig.iisUser "ReadAndExecute" # TODO: Give execute access to main dir, might want to lock down better.
    if (! $(Try { Test-Path $installPath } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $installPath 
    }
    Set-PermissionsOnPath $installPath $iisConfig.iisUser "ReadAndExecute" # TODO: Give read and execute access to install dir.
    if (! $(Try { Test-Path $downloadPath } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $downloadPath
    }
    Set-PermissionsOnPath $downloadPath $iisConfig.iisUser "Modify" # TODO: Modify access to downloads for IIS.
    if (! $(Try { Test-Path $appLogPath } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $appLogPath
    }
    Set-PermissionsOnPath $appLogPath $iisConfig.iisUser "Modify" # TODO: Modify access to log dir for IIS.
    if (! $(Try { Test-Path $dataFilePath } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $dataFilePath
    }
    Set-PermissionsOnPath $dataFilePath $iisConfig.iisUser "NoAccess" # TODO: Block IIS on data files.
    if (! $(Try { Test-Path $logFilePath } Catch { $false }) ) {
        New-Item -ItemType Directory -Force -Path $logFilePath
    }
    Set-PermissionsOnPath $logFilePath $iisConfig.iisUser "NoAccess" # TODO: Block IIS on log files.
    #
    # 2. Add main virtual directory for this Ed-Fi Suite to IIS
    $tooVerbose=New-WebVirtualDirectory -Site $iisConfig.defaultSiteName -Name $virtualDirectoryName -PhysicalPath $installPath -Force
    Write-Verbose "New-WebVirtualDirectory: $tooVerbose"
    #
    # Binaries Metadata
    $binaries = @(  
                    @{  name = "Api"; type = "WebApp";
                        requiredInInstallTypes = @("Production","Staging","Sandbox")
                        url = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.WebApi.EFA/$SuiteVersion";
                        iisAuthentication = @{ "anonymousAuthentication" = $true 
                                                "windowsAuthentication" = $false
                                             }
                        envAppSettings = @{
                            v260 = @{ 
                                       Production = @{ "owin:appStartup" = 'SharedInstance'; };
                                       Staging    = @{ "owin:appStartup" = 'SharedInstance'; };
                                       Sandbox    = @{ "owin:appStartup" = 'ConfigSpecificSandbox' };
                                    }
                            v320 = @{  
                                        Production = @{ "apiStartup:type" = 'SharedInstance' };
                                        Staging    = @{ "apiStartup:type" = 'SharedInstance' };
                                        Sandbox    = @{ "apiStartup:type" = 'Sandbox' };
                                    }
                            v330 = @{  
                                        Production = @{ "apiStartup:type" = 'SharedInstance' };
                                        Staging    = @{ "apiStartup:type" = 'SharedInstance' };
                                        Sandbox    = @{ "apiStartup:type" = 'Sandbox' };
                                    }
                            v340 = @{  
                                        Production = @{ "apiStartup:type" = 'SharedInstance' };
                                        Staging    = @{ "apiStartup:type" = 'SharedInstance' };
                                        Sandbox    = @{ "apiStartup:type" = 'Sandbox' };
                                    }
                        }
                        databases = @(  #all InstallTypes
                                        @{src="EdFi_Admin";dest="$($dbNamePrefix)_EdFi_Admin_$dbNameSufix"}
                                        @{src="EdFi_Security";dest="$($dbNamePrefix)_EdFi_Security_$dbNameSufix"}
                                        # InstallType Specific
                                        @{src="EdFi_Ods_Minimal_Template";dest="$($dbNamePrefix)_EdFi_Ods_$dbNameSufix";InstallType="Production"}
                                        @{src="EdFi_Ods_Populated_Template";dest="$($dbNamePrefix)_EdFi_Ods_$dbNameSufix";InstallType="Staging"}
                                        @{src="EdFi_Ods_Minimal_Template";dest="$($dbNamePrefix)_EdFi_Ods_Minimal_Template_$dbNameSufix";InstallType="Sandbox"}
                                        @{src="EdFi_Ods_Populated_Template";dest="$($dbNamePrefix)_EdFi_Ods_Populated_Template_$dbNameSufix";InstallType="Sandbox"}
                                    )
                        envConnectionStrings = @{
                            Production = @{
                                            "EdFi_Ods"               = "Server=.; Database=$($dbNamePrefix)_EdFi_ODS_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Admin"             = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Security"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_master"            = "Server=.; Database=master; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "BulkOperationDbContext" = "Server=.; Database=$($dbNamePrefix)_EdFi_Bulk_$dbNameSufix; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
                                          }
                            Staging = @{
                                            "EdFi_Ods"               = "Server=.; Database=$($dbNamePrefix)_EdFi_ODS_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Admin"             = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Security"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_master"            = "Server=.; Database=master; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "BulkOperationDbContext" = "Server=.; Database=$($dbNamePrefix)_EdFi_Bulk_$dbNameSufix; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
                                          }
                            Sandbox = @{
                                            "EdFi_Ods"               = "Server=.; Database=EdFi_{0}; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Admin"             = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Security"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_master"            = "Server=.; Database=master; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "BulkOperationDbContext" = "Server=.; Database=$($dbNamePrefix)_EdFi_Bulk_$dbNameSufix; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
                                        };
                        }
                        logFile = @{ "file" = "$appLogPath\ODSAPI-$logFileSuffix-log.txt" };
                    }
                    @{  name="Dbs"; type="Databases"; 
                        requiredInInstallTypes = @("Production","Staging","Sandbox")
                        url="http://www.toolwise.net/EdFi v$SuiteVersion databases with Sample Ext.zip"; }
                    @{  name="SandboxAdmin"; type="WebApp";
                        description = "This is the SandboxAdmin tool.";
                        requiredInInstallTypes = @("Sandbox")
                        InstallType = "Sandbox";
                        url="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.Admin.Web.EFA/$SuiteVersion"
                        urlVersionOverride = @{
                            v340 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.Admin.Web.EFA/3.3.0"
                        }
                        iisAuthentication = @{ "anonymousAuthentication" = $true 
                                                "windowsAuthentication" = $false
                                            }
                        connectionStrings = @{
                                            "EdFi_Ods"                   = "Server=.; Database=EdFi_{0};      Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Admin"                 = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix;    Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_Security"              = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                                            "EdFi_master"                = "Server=.; Database=master;        Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                                            "UniqueIdIntegrationContext" = "Server=.; Database=$($dbNamePrefix)_UniqueId_$dbNameSufix;     Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
                                            };
                        appSettings = @{ "apiStartup:type" = 'Sandbox' };
                        webConfigTagInsert = @{"//initialization" = '<users><add name="Test Admin" email="test@ed-fi.org" password="***REMOVED***" admin="true" /></users>'};
                        webConfigTagPostInstall = @{"//initialization" = ''};
                        webConfigAttributePostInstall = New-Object PSObject -Property @{ xPath="//initialization";attribute="enabled";value="False"}
                        logFile = @{ "file" = "$appLogPath\SandboxAdmin-$logFileSuffix-log.txt" };
                    }
                    @{  name="Docs"; type="WebApp";
                        description="This is the Swagger Api Docs web site.";
                        requiredInInstallTypes = @("Production","Staging","Sandbox")
                        url="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.SwaggerUI.EFA/$SuiteVersion";
                        urlVersionOverride = @{
                            v340 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.SwaggerUI.EFA/3.3.0"
                        }
                        iisAuthentication = @{ "anonymousAuthentication" = $true 
                                                "windowsAuthentication" = $false
                                            }
                        envAppSettings = @{
                            v260 = @{ "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/{section}/api-docs" }
                            v320 = @{
                                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                                "swagger.webApiVersionUrl"  = "$apiBaseUrl" };
                            v330 = @{
                                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                                "swagger.webApiVersionUrl"  = "$apiBaseUrl" };
                            v340 = @{
                                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                                "swagger.webApiVersionUrl"  = "$apiBaseUrl" };
                        };
                    }
                    @{ name="AdminApp";
                        description="This is the Production\SharedInstance AdminApp. Not to be confucesd with the SandboxAdmin.";
                        type="WebApp";
                        requiredInInstallTypes = @("Production","Staging")
                        url="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/$SuiteVersion";
                        urlVersionOverride = @{
                            v340 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/3.3.0"
                            v320 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/3.2.0.1"
                            v250 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/2.5.1"
                        }
                        iisAuthentication = @{ 
                                                "anonymousAuthentication" = $false
                                                "windowsAuthentication" = $true
                                            }
                        appSettings = @{
                                        "ProductionApiUrl" = "$appsBaseUrl/api"
                                        "SwaggerUrl" = "$appsBaseUrl/docs"
                                    };
                        connectionStrings = @{
                                                "EdFi_Ods_Production" = "Server=.; Database=$($dbNamePrefix)_EdFi_Ods_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
                                                "EdFi_Admin"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
                                                "EdFi_Security"       = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
                                            };
                        logFile = @{ "file" = "$appLogPath\AdminApp-$logFileSuffix-log.txt" };
                        secretJsonv260 = @{"AdminCredentials.UseIntegratedSecurity"=$true};
                    }
                )

    #
    # Create a table to collect the URLs for later use
    $appURLTable = @(
        @{ name= "Ed-Fi API $virtualDirectoryName"; type= "URL"; URI="/$virtualDirectoryName/api" }
    )
    #
    # 3. Download, extract/install, and set permissions for all listed binaries
    #
    foreach ($b in $binaries | Where-Object {($_.requiredInInstallTypes.Contains($InstallType)) -or (!$_.requiredInInstallTypes)}) {
        # Concatenate path for binary from name and dl location.
        # Note: all NuGet packages are zips.
        $dlFilePath = "$downloadPath\$($b.name)$SuiteVersion.zip"
        $pkgInstallPath = "$installPath\$($b.name)"
        $downloadUrl = $b.url
        if($b.urlVersionOverride -and $b.urlVersionOverride[$versionNum]){ $downloadUrl = $b.urlVersionOverride[$versionNum] }
        Copy-WebArchive -Url $downloadUrl -InstallPath $pkgInstallPath -FilePath $dlFilePath
        $AccessPermissions="ReadAndExecute"
        if ($b.name -eq "AdminApp") { $AccessPermissions="Modify" }
        Set-PermissionsOnPath $pkgInstallPath $iisConfig.iisUser $AccessPermissions
    }
    # 4. Loop back over webapps and add them to IIS, then update Web.config values AppSettings, ConnStrings and Log Files
    foreach ($b in $binaries | Where-Object {($_.type -eq "WebApp") -and (($_.requiredInInstallTypes.Contains($InstallType)) -or (!$_.requiredInInstallTypes))}) {
        $appName = $b.name
        $appPhysicalPath = "$installPath\$appName"
        $applicationIISPath = "$($iisConfig.defaultSiteName)/$virtualDirectoryName/$appName"
        $tooVerbose=New-WebApplication -Name $appName  -Site "$($iisConfig.defaultSiteName)\$virtualDirectoryName" -PhysicalPath $appPhysicalPath -ApplicationPool $($iisConfig.applicationPool) -Force
        Write-Verbose "New-WebApplication: $tooVerbose"
        # Add URL of app to table
        if ($b.name -ne "Api") {
            $appURLTable += @{ name="Ed-Fi $($b.name) $virtualDirectoryName"; type="URL"; URI="/$virtualDirectoryName/$($b.name)"}
        }    
        # Set IIS Authentication settings
        if($b.iisAuthentication) {
            foreach($key in $b.iisAuthentication.Keys) {
                Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$key" -Name Enabled -Value $b.iisAuthentication.Item($key) -PSPath IIS:\ -Location "$applicationIISPath"
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
                $secretJsonPhysicalPath = "$installPath\$($b.name)\secret.json"
                Set-IntegratedSecurityInSecretJsonFile($secretJsonPhysicalPath)
            }

            if($b.name -eq "Docs") {
                $swaggerDefaultHtmlPath = "$installPath\$($b.name)\default.html"
                Set-DocsHTMLPathsToWorkWithVirtualDirectories($swaggerDefaultHtmlPath)
            }
        }
    }
    # 5. Restore downloaded databases
    $apiDatabases = ($binaries | Where-Object {$_.name -eq "Api"}).databases;
    foreach($db in $apiDatabases | Where-Object {($_.InstallType -eq $InstallType) -or (!$_.InstallType)}) {
        $dbBackupFile = "$backupLocation\$($db.src).bak"
        Restore-Database $db.src $db.dest $dbBackupFile $dataFilePath $logFilePath
    }

    # 6. Setup Sandbox types

    if($InstallType -eq "Sandbox") {
        #Some sites like the Sandbox Admin need to be initiallized and then Web.Config updated.
        if($InstallType -eq "Sandbox"){ Initialize-Url "$appsBaseUrl/SandboxAdmin" }

        foreach ($b in $binaries | Where-Object {($_.type -eq "WebApp") -and (($_.requiredInInstallTypes.Contains($InstallType)) -or (!$_.requiredInInstallTypes))}) 
        {
            $appPhysicalPath = "$installPath\$($b.name)\Web.Config"

            if($b.webConfigTagPostInstall){ 
                Set-TagInWebConfig $appPhysicalPath $b.webConfigTagPostInstall
            }

            if($b.webConfigAttributePostInstall){
                Set-AttributeValueInWebConfig $appPhysicalPath $b.webConfigAttributePostInstall.xPath $b.webConfigAttributePostInstall.attribute $b.webConfigAttributePostInstall.value
            }
        }
    }

    # 7. Install Analytics Middle Tier to ODS table, won't have much effect on a Sandbox env but should still work
    if ($odsName -ne "") {
        Install-AMT $EdFiDir $SuiteVersion $odsName
    }
    
    # 8. Add URLs for all Apps to desktop
    if (!(Get-Command "Add-DesktopAppLinks" -ErrorAction SilentlyContinue)) {
        Import-Module .\EdFiBinaryInstaller.psm1
    }
    Add-DesktopAppLinks $appURLTable
    Add-WebAppLinks -AppURIs $appURLTable -DnsName $DnsName -SolutionName "Ed-Fi Tools for ODS/API v$SuiteVersion" # -EdFiWebDir $SolutionWebRoot

}
# Region: Web.Config Functions

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
Function Restore-Database($dbSource, $dbDestinationName, $dbBackupPath, $dataFilePath, $logFilePath) {
    Write-Verbose "Restore database $dbSource as $dbDestinationName from file $dbBackupPath on datapath $dataFilePath logpath $logFilePath"
    $server = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
    if($null -eq $dataFilePath) {$dataFilePath = $(if ($server.Settings.DefaultFile) {$server.Settings.DefaultFile} else {$server.Information.MasterDBPath})}
    if ($null -eq $logFilePath) {$logFilePath = $(if ($server.Settings.DefaultLog) {$server.Settings.DefaultLog} else {$server.Information.MasterDBLogPath})}
    $dbRestorePath = "$dataFilePath\$dbDestinationName.mdf"
    $logRestorePath = "$logFilePath\$dbDestinationName.ldf"

    $backupDeviceItem = New-Object Microsoft.SqlServer.Management.Smo.BackupDeviceItem -ArgumentList $dbBackupPath,'File'
    $restore = New-Object Microsoft.SqlServer.Management.Smo.Restore
    $restore.Database = $dbDestinationName
    $restore.Devices.Add($backupDeviceItem)
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
        $restore.RelocateFiles.Add($relocateFile) 
    }
    try {
        $restore.SqlRestore($server)
    }
    catch {
        Write-Error "Exception: $($_.Exception) Details: $_"
    }
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