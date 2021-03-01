@(
        @{
            name="v501-Demo";
            description="Ed-Fi Suite 3 v5.0.1 Demo";
            archives=@(
                @{name="api"; filename="Api_v501.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi.Ods.WebApi.zip"},
                @{name="ApiDocs"; filename="Docs_v501.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi.Ods.SwaggerUI.zip"},
                @{name="AdminApp"; filename="AdminApp_v501.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi.Ods.AdminApp.Web.zip"}
                @{name="EdFi_Admin_Demo_v501"; filename="EdFiAdmin_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Admin.bak"}
                @{name="EdFi_Security_Demo_v501"; filename="EdFiSecurity_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Security.bak"}
                @{name="EdFi_Ods_Demo_v501"; filename="EdFiOds_Popuplated_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Ods_Populated_Template.bak"}
                @{name="EdFi_Ods_Demo_v501"; filename="EdFiOds_pgsql_Popuplated_v501.bak"; type="pgsql"; archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.Ods.Populated.Template.PostgreSQL/5.0.1"}
            )
            apps=@(
                @{name="api"; config=@(
                    @{path="/system.webServer/security/authentication";name="anonymousAuthentication";value=$true},
                    @{path="/system.webServer/security/authentication";name="windowsAuthentication";value=$false},
                    @{path="//appSettings";name="ProductionApiUrl";value="$appsBaseUrl/api"},
                    @{path="//appSettings";name="apiStartup:type";value="SharedInstance"},
                    @{path="//connectionStrings";name="EdFi_Ods";value="Server=.; Database=EdFi_Ods_Demo_v501; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"},
                    @{path="//connectionStrings";name="EdFi_Admin";value="Server=.; Database=EdFi_Admin_Demo_v501; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"},
                    @{path="//connectionStrings";name="EdFi_Security";value="Server=.; Database=EdFi_Security_Demo_v501; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"},
                    @{path="//connectionStrings";name="BulkOperationDbContext";value="Server=.; Database=EdFi_Bulk_Demo_v501; Trusted_Connection=True; MultipleActiveResultSets=True; Application Name=EdFi.Ods.WebApi;"}
                ) },
                @{name="ApiDocs"; config=@(
                    @{path="/system.webServer/security/authentication";name="anonymousAuthentication";value=$true},
                    @{path="/system.webServer/security/authentication";name="windowsAuthentication";value=$false},
                    @{path="//appSettings";name="swagger.webApiMetadataUrl";value="$apiBaseUrl/metadata/"},
                    @{path="//appSettings";name="swagger.webApiVersionUrl";value="$apiBaseUrl"}
                ) },
                @{name="AdminApp"; config=@(
                    @{path="/system.webServer/security/authentication";name="anonymousAuthentication";value=$true},
                    @{path="/system.webServer/security/authentication";name="windowsAuthentication";value=$false},
                    @{path="//appSettings";name="ProductionApiUrl";value="$appsBaseUrl/api"},
                    @{path="//appSettings";name="apiStartup:type";value="SharedInstance"},
                    @{path="//connectionStrings";name="EdFi_Ods_Production";value="Server=.; Database=EdFi_Ods_Demo_v501; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"},
                    @{path="//connectionStrings";name="EdFi_Admin";value="Server=.; Database=EdFi_Admin_Demo_v501; Trusted_Connection=True; Application Name=EdFi.Ods.WebApi;"},
                    @{path="//connectionStrings";name="EdFi_Security";value="Server=.; Database=EdFi_Security_Demo_v501; Trusted_Connection=True; Persist Security Info=True; Application Name=EdFi.Ods.WebApi;"},
                ) }
            );
        },
        @{
            name="v501-Test";
            description="Ed-Fi Suite 3 v5.0.1 Test";
            archives=@(
                @{name="api"; filename="Api_v501.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi.Ods.WebApi.zip"},
                @{name="AdminApp"; filename="AdminApp_v501.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi.Ods.AdminApp.Web.zip"}
                @{name="EdFi_Admin_Test_v501"; filename="EdFiAdmin_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Admin.bak"}
                @{name="EdFi_Security_Test_v501"; filename="EdFiSecurity_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Security.bak"}
                @{name="EdFi_Ods_Test_v501"; filename="EdFiOds_Minimal_v501.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/5.0.1/EdFi_Ods_Minimal_Template.bak"}
                @{name="EdFi_Ods_Test_v501"; filename="EdFiOds_pgsql_Minimal_v501.bak"; type="pgsql"; archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.Ods.Minimal.Template.PostgreSQL/5.0.1"}
            )
            apps=@(
                @{name="api"; config=""},
                @{name="AdminApp"; config=""}
            );
        },
        @{
            name="v341-Demo";
            description="Ed-Fi Suite 3 v3.4.1 Demo";
            archives=@(
                @{name="api"; filename="Api_v341.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi.Ods.WebApi.zip"},
                @{name="ApiDocs"; filename="Docs_v341.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi.Ods.SwaggerUI.zip"},
                @{name="AdminApp"; filename="AdminApp_v341.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi.Ods.AdminApp.Web.zip"}
                @{name="EdFi_Admin_Demo_v341"; filename="EdFiAdmin_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Admin.bak"}
                @{name="EdFi_Security_Demo_v341"; filename="EdFiSecurity_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Security.bak"}
                @{name="EdFi_Ods_Demo_v341"; filename="EdFiOds_Popuplated_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Ods_Populated_Template.bak"}
                @{name="EdFi_Admin_Demo_v341"; filename="EdFiAdmin_v341.sql"; type="pgsql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Admin.sql"}
                @{name="EdFi_Security_Demo_v341"; filename="EdFiSecurity_v341.sql"; type="pgsql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Security.sql"}
                @{name="EdFi_Ods_Demo_v341"; filename="EdFiOds_pgsql_Popuplated_v341.bak"; type="pgsql"; archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.Ods.Populated.Template.PostgreSQL/3.4.1"}
            )
            apps=@(
                @{name="api"; config=""},
                @{name="ApiDocs"; config=""},
                @{name="AdminApp"; config=""}
            );
        },
        @{
            name="v341-Test";
            description="Ed-Fi Suite 3 v3.4.1 Test";
            archives=@(
                @{name="api"; filename="Api_v341.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi.Ods.WebApi.zip"},
                @{name="AdminApp"; filename="AdminApp_v341.zip"; type="webapp"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi.Ods.AdminApp.Web.zip"}
                @{name="EdFi_Admin_Test_v341"; filename="EdFiAdmin_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Admin.bak"}
                @{name="EdFi_Security_Test_v341"; filename="EdFiSecurity_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Security.bak"}
                @{name="EdFi_Ods_Test_v341"; filename="EdFiOds_Minimal_v341.bak"; type="mssql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Ods_Minimal_Template.bak"}
                @{name="EdFi_Admin_Test_v341"; filename="EdFiAdmin_v341.sql"; type="pgsql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Admin.sql"}
                @{name="EdFi_Security_Test_v341"; filename="EdFiSecurity_v341.sql"; type="pgsql"; archive="https://odsassets.blob.core.windows.net/public/CloudOds/deploy/release/3.4.1/EdFi_Security.sql"}
                @{name="EdFi_Ods_Test_v341"; filename="EdFiOds_pgsql_Minimal_v341.bak"; type="pgsql"; archive="https://www.myget.org/F/ed-fi/api/v2/package/EdFi.Suite3.Ods.Minimal.Template.PostgreSQL/3.4.1"}
           )
            apps=@(
                @{name="api"; config=""},
                @{name="AdminApp"; config=""}
            );
        }
)