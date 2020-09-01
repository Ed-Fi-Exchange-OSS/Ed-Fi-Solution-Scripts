# Config files for the Ed-Fi-Solution-Scripts
You can manage the parameters used by these install scripts in the file:

See below for more on the these tools themselves.
## Base Config:
### Command line options for installer
The following parameters can be specified on the command line or via JSON config file using
    ```powershell
       install_solution.ps1 -config EdFiBaseConfig.json
    ```
#### Parameters:
* "installType": Whether to use a production-like staging environment or install sample data and demonstration artifacts,  options="Staging","Demo",  default="Demo"
* "EdFiDir": path to all things Ed-Fi,  default="C:\\Ed-Fi"
* "DnsName": DNS name chosen for this environment,  example:"demo.agency.org"
* "AdminEmail": An administrative contact email needed when generating SSL certificates within the demo,  example:"info@agency.org"
* "DDNSUrl": Simple API URL for dynamic DNS provider accepting DNS name and IP address to update, examples (use the actual URL in config file with backtick in front of ampersand):["Dyn.com"]("https://members.dyndns.org/nic/update?hostname={DnsName}`&myip={IP}") , ["YDNS"]("https://ydns.io/api/v1/update/?host={DnsName}`&ip={IP}"), ["FreeDNS"]("https://freedns.afraid.org/nic/update?hostname={DnsName}`&myip={IP}")
* "DDNSUsername": Username to pass in for HTTPS authentication to Dynamic DNS provider
* "DDNSPassword": And your password for dynamic DNS

### Additional config settings

In addtion to all of the command line parameters, the following configuration settings may be modified/specified in the config file only:
#### JSON Elements
* "DownloadPath": example:"C:\\Ed-Fi\\Downloads", default=("Downloads" under "EdFiDir")
* "SolutionWebRoot": "C:\\Ed-Fi\\www",  default=("www" under "EdFiDir")
* "GitPAT": "GitHub Personal Access Token", [See Developer Settings under your Profile](https://github.com/settings/profile)
* "SolutionsAppName": Name of installed Web App,  default="EdFiSolutions"
* "MSSQLEURL": default:(full URL for SQL Server Express 2019)
* "MSSQLINST": default:"MSSQLSERVER"
* "dotnetcorePackage": defaults:
     * "package":"dotnetcore-windowshosting"
     *  "version":"2.2.8"
* "baseChocoPackages": A space-separated list of base packages to install before any others, NOTE: all defaults are required but you can specify matching substitutes or additional pre-reqs.  default:"netfx-4.8-devpack dotnetcore-sdk nuget.commandline urlrewrite git win-acme"
* "selectedChocoPackages": These are key additional tools that may not be needed for all solutions or must be installed after the base packages.  default:"postgresql sql-server-management-studio",
* "optionalChocoPackages": These are optional packages not needed for a server-only installation.  default:"microsoft-edge firefox"

## Solutions Configuration:

### Command line option to installer:

There are two options for solutions which can be specified on the command line:
    ```powershell
    install_solution.ps1 -solutions EdFiSolutionsConfig.json -SolutionName <solution>
    ```
* -solutions: file name of solutionsconfig.json,   default:EdFiSolutionsConfig.json
* -SolutionName: name of the solution listed in config file to install,   default:(all)

### Solutions config file

#### JSON Elements
Structure/Example of JSON file:
```JSON
    "solutions": [
        {   "name": "SolutionA",
            "chocoPackages": "<addtional packages>",
            "repo": "github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts",
            "archive": "<zip file to download instead of repo>",
            "installSubPath": "scripts",
            "installer": "install.ps1",
            "EdFiVersion": "3.4.0",
            "appLinks": [
                {"type": "File", "name": "Installer files", "URI": "scripts" },
                {"type": "URL", "name": "Installer on GitHub", "URI": "https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts" },
                {"type": "URL", "name": "Solution Starter Kit Guides", "URI": "https://techdocs.ed-fi.org/display/ETKB/Ed-Fi+Solution+Starter+Kit+Guides" },
                {"type": "URL", "name": "Ed-Fi Home", "URI": "https://www.ed-fi.org" },
                {"type": "URL", "name": "Ed-Fi TechDocs", "URI": "https://techdocs.ed-fi.org" }
            ]
        },
        ...
    ]
```
* name: must not contain spaces
* chocoPackages: installed after other pre-reqs and after Ed-Fi Suite is installed
* repo:  URL can be a full URL with HTTPS, or can exclude https to attach the GitHub PAT for authentication to private repositories.  (HTTPS is always used.)
* archive: use instead of repo to download and extract a zip file to the path specified
* installSubPath: path under the EdFiDir to install this solution
* EdFiVersion: The most current version of the EdFi Suite supported by this solution
* appLinks: A list of URLs or local files to add to the desktop and list in the default /EdFi homepage on the local server
    * type: File or URL
    * URI:  the URI can be relative or absolute, relative URLs will have the given name or "localhost" prepended.
    * Name: name assigned to hyperlink/shortcut

## Config file examples
Please refer to the Solution Starter Kit Guides on Ed-Fi Techdocs to get started.
1. [Example Base Config file](https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts/blob/master/EdFiBaseConfigExample.json)
1. [Another Base Config file](https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts/blob/master/EdFiBaseConfigExample.json)
