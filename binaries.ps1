@(  
    @{  name = "Api"; type = "WebApp";
        requiredInInstallTypes = @("Staging", "Demo")
        url = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.WebApi.EFA/$SuiteVersion";
        iisAuthentication = @{ "anonymousAuthentication" = $true 
            "windowsAuthentication"                      = $false
        }
        envAppSettings = @{
            v260 = @{ 
                Staging = @{ "owin:appStartup" = 'SharedInstance'; };
                Demo    = @{ "owin:appStartup" = 'SharedInstance'; };
            }
            v320 = @{  
                Staging = @{ "apiStartup:type" = 'SharedInstance' };
                Demo    = @{ "apiStartup:type" = 'SharedInstance' };
            }
            v330 = @{  
                Staging = @{ "apiStartup:type" = 'SharedInstance' };
                Demo    = @{ "apiStartup:type" = 'SharedInstance' };
            }
            v340 = @{  
                Staging = @{ "apiStartup:type" = 'SharedInstance' };
                Demo    = @{ "apiStartup:type" = 'SharedInstance' };
            }
        }
        databases = @(  #all InstallTypes
            @{src = "EdFi_Admin"; dest = "$($dbNamePrefix)_EdFi_Admin_$dbNameSufix" }
            @{src = "EdFi_Security"; dest = "$($dbNamePrefix)_EdFi_Security_$dbNameSufix" }
            # InstallType Specific
            @{src = "EdFi_Ods_Minimal_Template"; dest = "$($dbNamePrefix)_EdFi_Ods_$dbNameSufix"; InstallType = "Staging" }
            @{src = "EdFi_Ods_Populated_Template"; dest = "$($dbNamePrefix)_EdFi_Ods_$dbNameSufix"; InstallType = "Demo" }
        )
        envConnectionStrings = @{
            Staging = @{
                "EdFi_Ods"               = "Server=.; Database=$($dbNamePrefix)_EdFi_ODS_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_Admin"             = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_Security"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_master"            = "Server=.; Database=master; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "BulkOperationDbContext" = "Server=.; Database=$($dbNamePrefix)_EdFi_Bulk_$dbNameSufix; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
            }
            Demo    = @{
                "EdFi_Ods"               = "Server=.; Database=$($dbNamePrefix)_EdFi_ODS_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_Admin"             = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_Security"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"
                "EdFi_master"            = "Server=.; Database=master; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"
                "BulkOperationDbContext" = "Server=.; Database=$($dbNamePrefix)_EdFi_Bulk_$dbNameSufix; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"
            }
        }
        logFile = @{ "file" = "$appLogPath\ODSAPI-$logFileSuffix-log.txt" };
    }
    @{  name = "Dbs"; type = "Databases"; 
        requiredInInstallTypes = @("Staging", "Demo")
        url = "http://www.toolwise.net/EdFi v$SuiteVersion databases with Sample Ext.zip"; 
    }
    @{  name = "Docs"; type = "WebApp";
        description = "This is the Swagger Api Docs web site.";
        requiredInInstallTypes = @("Staging", "Demo")
        url = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Ods.SwaggerUI.EFA/$SuiteVersion";
        iisAuthentication = @{ "anonymousAuthentication" = $true 
            "windowsAuthentication"                      = $false
        }
        envAppSettings = @{
            v260 = @{ "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/{section}/api-docs" }
            v320 = @{
                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                "swagger.webApiVersionUrl"  = "$apiBaseUrl" 
            };
            v330 = @{
                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                "swagger.webApiVersionUrl"  = "$apiBaseUrl" 
            };
            v340 = @{
                "swagger.webApiMetadataUrl" = "$apiBaseUrl/metadata/"
                "swagger.webApiVersionUrl"  = "$apiBaseUrl" 
            };
        };
    }
    @{ name                    = "AdminApp";
        description            = "This is the Production-style\SharedInstance AdminApp. Not to be confused with the SandboxAdmin.";
        type                   = "WebApp";
        requiredInInstallTypes = @("Staging", "Demo")
        url                    = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/$SuiteVersion";
        urlVersionOverride     = @{
            v320 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/3.2.0.1"
            v250 = "https://www.myget.org/F/ed-fi/api/v2/package/EdFi.ODS.AdminApp.Web/2.5.1"
        }
        iisAuthentication      = @{ 
            "anonymousAuthentication" = $false
            "windowsAuthentication"   = $true
        }
        appSettings            = @{
            "ProductionApiUrl" = "$appsBaseUrl/api"
            "SwaggerUrl"       = "$appsBaseUrl/docs"
        };
        connectionStrings      = @{
            "EdFi_Ods_Production" = "Server=.; Database=$($dbNamePrefix)_EdFi_Ods_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
            "EdFi_Admin"          = "Server=.; Database=$($dbNamePrefix)_EdFi_Admin_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
            "EdFi_Security"       = "Server=.; Database=$($dbNamePrefix)_EdFi_Security_$dbNameSufix; Trusted_Connection=True; Application Name=EdFi.AdminApp;"
        };
        logFile                = @{ "file" = "$appLogPath\AdminApp-$logFileSuffix-log.txt" };
        secretJsonv260         = @{"AdminCredentials.UseIntegratedSecurity" = $true };
    }
)
