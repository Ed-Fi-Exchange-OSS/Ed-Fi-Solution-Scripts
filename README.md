# Ed-Fi-Solution-Scripts
## Starter Kits
These scripts should be paired with the [Starter Kits on Ed-Fi Techdocs](https://techdocs.ed-fi.org/display/SK/Starter+Kits) Go here first to get started.

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
