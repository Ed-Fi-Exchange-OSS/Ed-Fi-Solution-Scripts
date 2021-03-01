@(
    @{
        name="s3v500";
        description="Ed-Fi Suite 3 v5.0.0 Tech Installer";
        chocoPackages="";repo="";archive="https://odsassets.blob.core.windows.net/public/techsuiteinstaller/Ed-Fi_Tech_Suite_September2020_ss.zip";
        installer=@{
            ScriptBlock={ Param ($toolsPath,$downloadPath) .\install.ps1 -toolsPath $toolsPath -downloadPath $downloadPath }
            ArgumentList="C:\Ed-Fi\Tools","C:\Ed-Fi\Downloads"
        }
    },
    @{
        name="s3";
        description="Ed-Fi Suite 3 current components";
        chocoPackages=""
        components=@{
            ODS=@{
                archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.RestApi.Databases/5.0.0"
                installSubPath="DatabasesSuite3v500"
                installer=@{
                    command="Import-Module Deployment.psm1 ; Initialize-DeploymentEnvironment"
                    arguments = @{
                        Engine = "SQLServer"
                        InstallType = "SharedInstance"
                        DropDatabases = $false
                        NoDuration = $true       
                        OdsDatabaseTemplateName = if ($InstallType -like "demo") {"populated"} else { "minimal" }
                    }
                }
            };
            API=@{
                archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.Ods.WebApi/5.0.0"
                installSubPath="DatabasesSuite3v500"
                installer=@{
                    command="Import-Module Deployment.psm1 ; Initialize-DeploymentEnvironment"
                    arguments = @{
                        Engine = "SQLServer"
                        InstallType = "SharedInstance"
                        DropDatabases = $false
                        NoDuration = $true       
                        OdsDatabaseTemplateName = if ($InstallType -like "demo") {"populated"} else { "minimal" }
                    }
                }

            }
        }
    }

)