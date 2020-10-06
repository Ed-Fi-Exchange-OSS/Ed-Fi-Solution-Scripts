# Ed-Fi Solution installers
These scripts are intended to work with Ed-Fi Starter Kits and simplify the process of preparing additional solutions to become Starter Kits as well.

## Installer

### Detailed System Requirements
We highly recommend that you do not use this installer on your personal workstation as it may conflict with your organization's security and network policies. 
Ideally, use a virtual machine platform, e.g. VMware, Hyper-V, or Virtual Box to run a standalone installation of Windows Server 2019.

Most solutions require a machine or virtual machine with internet access and these Minimum system requirements:
* 50GB free storage space (before any data is loaded)
* 4GB of available RAM
* Windows Server 2019 (or 2016)
* Access to inbound and outbound connections over HTTPS as well as ephemeral ports (usually 20,000-65,535) used by the web server and, if used, the remote desktop service.

Preferred requirements
* 1TB storage space
* 8-16GB RAM
* An assigned DNS name mapped to a public IP or reverse proxy front-end
* Access to HTTP on port 80 is required for the installer to generate SSL certificates automatically

Optional
* If you have access to dynamic DNS services, you can use that to configure your system build.  See Config.md for details.

Most solutions will require a running instance of SQL Server, thus the scripts will automatically install SQL Server Express 2019 if no instance is found.
If you do have a license for Microsoft SQL Server, please install it before starting here, or for cloud installations choose an image that includes it.

### On your own Windows Server:
This guide generally assumes default installation choices, but if at any point you have customized your environment, you can use the advanced installation path to adjust this installer to your environment.

#### Automated installation of a base Ed-Fi Installation:
***
1. Open a Windows PowerShell (Admin) command prompt.\
    From the **Windows Menu**, search for **PowerShell**, right click on it, and select **Run as Administrator**
1. Run the installer by pasting this command in to the PowerShell window:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts/raw/master/install.ps1'))
    ```
1. When run without parameters the installer will prompt you to pick a solution to install.  Choose the appropriate base installation for your needs and continue.
1. The installer will take about 60-90 mins to download and install the components of your solution.
1. When complete, you will find an **Ed-Fi Solutions** folder with a link to the Admin App for your installation.
1. Refer to [Ed-Fi Techdocs](https://techdocs.ed-fi.org/) for more details on configuring and using your installation.

#### Advanced installation:
***
1. Copy the files in this repository to the C:\Ed-Fi folder on your installation environment  
    * [Download ZIP](https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts/archive/master.zip) and uncompress it to **C:\Ed-Fi**
    * Or use Git to clone the repo to your system:
    ```powershell
    git clone https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts.git C:\Ed-Fi
    ```
1. Edit the **EdFiBaseConfig.json** and **EdFiSolutionConfig.json** files to adjust any configuration details for the installer.
    * See the Configuration Guide for more details.
1. From an elevated PowerShell command prompt,\
    From the **Windows Menu**, search for **PowerShell**, right click on it, and select **Run as Administrator**
1. Change to the **C:\Ed-Fi** directory and launch the installer:\
    ```powershell
    cd \Ed-Fi
    .\install_solution.ps1 -Verbose -SolutionName base -noui
    ```
1. Watch for the "Installation complete" message.
1. Reboot your system and when you log in again, you'll see an **Ed-Fi Solutions** folder on your desktop
1. When complete, you will find an **Ed-Fi Solutions** folder with a link to the Admin App for your installation.
1. Refer to [Ed-Fi Techdocs](https://techdocs.ed-fi.org/) for more details on configuring and using your installation.

#### Troubleshooting the installer
***
* If you run into trouble with the installation, you can take a look in the **C:\Ed-Fi\Logs\install** folder for the **solution_install.log** file.
* In most cases you can safely ignore warnings about existing software installations, but please note, these solutions may not be tested with older versions or with recently released versions of those software products.
* Connect with us on the #users-solutions channel if you have questions.

### On AWS, 
#### Using  Cloud Formation
1. You can download the Cloud Formation template file: [EdFiSolutions-AWS-CloudFormation-Win2019-SingleVM.json](https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts/raw/master/AWS/EdFiSolutions-AWS-CloudFormation-Win2019-SingleVM.json) or you can use the [AWS S3 copy](https://s3-us-west-1.amazonaws.com/winami3.lambda.edfi.org/EdFiSolutions-AWS-CloudFormation-Win2019-SingleVM.json)
1. Connect to your AWS Console:\
    `If using your organization's AWS account, check with your system administrators to verify that you have the correct access rights. Admin rights are required to create AWS EC2 instances and other components for your solution.`
1. Navigate to Cloud Formation under the Management & Governance section of the Services menu
1. Select Create Stack
1. Select Amazon S3 URL and enter https://s3-us-west-1.amazonaws.com/winami3.lambda.edfi.org/EdFiSolutions-AWS-CloudFormation-Win2019-SingleVM.json  -or-  Select "Upload a template File" and choose the file you downloaded in the first step
1. Follow the direction in the template to complete your solution setup

#### Launching an EC2 instance directly
1. Navigate to the EC2 Instances dashboard
1. Select **Launch Instance**
1. Choose a base Windows Server image or select an image with Microsoft SQL Server Standard edition installed
1. You may choose any size of virtual machine you like but note that SQL Server will generally require at least 4 GB of RAM.
1. On the Advanced

### On Azure:
1. Open your Azure management portal\
    `If using your organization's account, check with your system administrators to verify that you have the correct access rights. Admin rights are required to create Azure resources such as virtual machine instances and other components for your solution.`
1. Launch a Windows VM and follow the process for on-premises installation

# About the Starter Kits and this installer
## Purpose of Starter Kits
Refer to [Starter Kits on Ed-Fi Techdocs](https://techdocs.ed-fi.org/display/SK/Starter+Kits)

## Building solutions to use with the Ed-Fi Technical Suite and the Starter Kits installer
The Starter Kits define the following components to use when building your own solutions for the Ed-Fi Community:
* Guide documents for each step of the solution's deployment-
  * **Install Guide** to walkthrough steps required to install your solution in an existing Ed-Fi environmnent, using all defaults and/or allowing for customization where appropriate
  * **Admin Guide** to provide for initial configuration and for regular work to configure/customize, administer, and maintain the solution beyond the core Ed-Fi guides
  * **User Guide** to, at minimum, take the installer or primary user through the fundamental "use case" this solution is meant to address. In addition, it should present a tutorial for each function or use case relevant to the end users of the solution. 
* Sample data needed to highlight the function of the solution. Provided sample data should use Ed-Fi core tools to load and can therefore extend or modify existing sample data sets.
* Provide automated install and configuration processes where possible by extending this installer as described in the Configuration Guide

## Using these tools
In order to quickly get a working solution environment, this code is meant to simplify the packaging and deployment of Ed-Fi-based solutions for demo and early testing purpose.  Paired with training content, a deployment team can use these as a reference as they plan and apply the solution deployment to their own environment.
### Important installation files:
* install.ps1
  * Can be launched directly on a base Windows Server instance/VM or passed in as a start script for launch of a Windows Azure Image or AWS EC2 Windows Server base instance.
* install_solution.ps1
  * Run this interactively from a PowerShell Admin prompt. Works with a base Windows Server installation (vers 2016-2019) to configure all pre-reqs, tools, and current Ed-Fi Tech Suites 2 & 3
* config\EdFiBaseConfig.json
  * Configuration details used by the installer, most defaults are appropriate for a new installation.
* config\EdFiBaseConfig.json
  * Specifies the details used to install a particular solution.
