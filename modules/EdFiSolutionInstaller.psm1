# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
Import-Module "$PSScriptRoot\edfi-installconfig"
Import-Module "$PSScriptRoot\edfi-netsetup"
Import-Module "$PSScriptRoot\edfi-websetup"
Import-Module "$PSScriptRoot\edfi-dbsrvsetup"

function Set-PermissionsOnPath {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory=$True)]$FilePath, 
        [Parameter(Mandatory=$True)]$User, 
        [Parameter(Mandatory=$True)]$Perms,
        $Inheritance
        )
    try 
    {
        $ACL = Get-Acl $FilePath
        $Account = New-Object System.Security.Principal.NTAccount($User)
        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
        $AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
        # Use default inheritance if none specified
        if ($null -eq $Inheritance) {
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else {
            if ($Inheritance -like "ObjectInherit") {
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                # We won't propagate the inheritance of those entries that are applied to this folder only
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
            }
            elseif ($Inheritance -like "ContainerInherit") {
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
            }
            else {
                # Fallback: just apply this to the path given and block both inheritance and propagation
                $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
            }
        }
        if ($Perms -like "NoAccess") {  # This is meant to Deny CRUD
            $FileSystemRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
            # First we have to remove inheritance while copying the existing rules in
            $ACL.SetAccessRuleProtection($true,$true)
            # Then, make that permanent before reloading the ACL
            Set-Acl $FilePath $ACL
            $ACL = Get-Acl $FilePath
            # This is mostly unused in a remove all except for the Account: 
            $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            # Now simply remove all ACL entries for this user/group
            $ACL.RemoveAccessRuleAll($FileSystemAccessRule)
        }
        else {
            $FileSystemRights = [System.Security.AccessControl.FileSystemRights]$Perms
            $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            $ACL.SetAccessRule($FileSystemAccessRule) # or $ACL.AddAccessRule($FileSystemAccessRule)
        }
        Set-Acl $FilePath $ACL
        Write-Verbose "Set permissions on path: $FilePath for user: $User to: $Perms"
    }
    catch {
        Write-Error "Unable to add user: $User to path: $FilePath with permissions: $Perms`n Error: $_"
    }
}
function Add-DesktopAppLinks {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $AppURIs,
        $solName=$null
    )
    # Example of what to pass in
    # $AppLinks = @( 
    #               @{ name= "Link to a file"; type= "File"; URI="relative\\path\\file.ext" };
    #               @{ name= "WebLnk"; type= "URL"; URI="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-ODS-AdminApp" }
    #             )
    #
    # Get Public Desktop to install links to Apps
    Write-Verbose "Adding Solution Links to Ed-Fi Solutions Folder on common Desktop"
    $pubDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
    $EdFiSolFolder="$pubDesktop\Ed-Fi Solutions"
    if ($null -ne $solName) {
        $EdFiSolFolder="$pubDesktop\Ed-Fi Solutions\$solName"
    }
    $WScriptShell = New-Object -ComObject WScript.Shell
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $EdFiSolFolder } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $EdFiSolFolder 
    }
    # Add URLs to public desktop
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "URL"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).url")
        $targetURL = $appInstall.URI
        if (!($targetURL -like "http*")) {
            $targetURL = $targetURL -Replace "^","https://localhost/"
        }
        $Shortcut.TargetPath = $targetURL
        $Shortcut.Save()
    }
    # Add File Links to public desktop, these can be regular files or programs
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "File"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).lnk")
        $Shortcut.TargetPath = $appInstall.URI
        $Shortcut.Save()
    }
    # Add File Links to public desktop, these can be regular files or programs
    foreach ($appInstall in $AppURIs | Where-Object {$_.type -eq "App"}) {
        $Shortcut = $WScriptShell.CreateShortcut("$EdFiSolFolder\$($appInstall.name).lnk")
        $Shortcut.TargetPath = "$($appInstall.command) $($appInstall.appfile)"
        $Shortcut.Save()
    }
}
    function Add-WebAppLinks {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $AppURIs,
            $DnsName="localhost",
            $SolutionName="Ed-Fi Tools",
            $WebPath="C:\Ed-Fi\www"
        )
        # Example of what to pass in
        # $appURLs = @( 
        #               @{ name= "Link to a file"; type= "File"; URI="relative\\path\\file.ext" };
        #               @{ name= "WebLnk"; type= "URL"; URI="https://github.com/Ed-Fi-Alliance-OSS/Ed-Fi-ODS-AdminApp" }
        #             )
        #
        Write-Verbose "Adding Solution Links to Ed-Fi Solutions website for local IIS homepage"
        $solHtmlFile="$WebPath\SolutionItems.html"
        if (! $(Try { Test-Path $solHtmlFile -ErrorAction SilentlyContinue } Catch { $false }) ) {
            if (! $(Try { Test-Path $EdFiWebDir -ErrorAction SilentlyContinue } Catch { $false }) ) {
                $tooVerbose = New-Item -ItemType Directory -Force -Path $WebPath
            }
            Set-Content $solHtmlFile ""
        }
        $solHtmlSections=@("")
        
        # Add regular URLs to section
        foreach ($appInstall in $AppURIs) {
            if ($appInstall.type -eq "URL") {
                $solHtmlSections+="<li><a href=`"$($appInstall.URI)`">$($appInstall.name)</a></li>`n"
            } elseif ($appInstall.type -eq "File") {
                $solHtmlSections+="<li><a href=`"file:$($appInstall.URI)`">$($appInstall.name)</a></li>`n"
            } elseif ($appInstall.type -eq "App") {
                $solHtmlSections+="<li><a href=`"file:$($appInstall.appfile)`">$($appInstall.name)</a></li>`n"
            } else {
                Write-Verbose "App link with type: $($appInstall.type)"
            }
        }
        $solTemplate =@"
        <li class="accordion-item is-active" data-accordion-item> <a href="#" class="accordion-title">$SolutionName</a>
            <div class="accordion-content" data-tab-content>
            <p><span style="font-weight: 400;">
                <ul>
                    $solHtmlSections
                </ul>
                </span></p>
            </div>
        </li>
"@
        Add-Content $solHtmlFile $solTemplate
        Write-Debug $solTemplate
    }
    function Publish-WebSite {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $SolutionWebDir="C:\Ed-Fi\www",
            $VirtualDirectoryName="EdFi",
            $AppName="EdFiSolutions",
            $iisConfig=@{ iisUser="IIS_IUSRS"; SiteName = "Ed-Fi"; applicationPool = "EdFiAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
        )
        Write-Verbose "Generating Ed-Fi Solutions website for local IIS homepage"
        $solutionsHtml="$SolutionWebDir\SolutionItems.html"
        $headerHtml="$SolutionWebDir\SolutionHeader.html"
        $footerHtml="$SolutionWebDir\SolutionFooter.html"
        $indexHtml="$SolutionWebDir\index.html"
        Set-PermissionsOnPath -FilePath $SolutionWebDir -User $iisConfig.iisUser -Perms "ReadAndExecute"
        Get-Content -Path $headerHtml | Set-Content $indexHtml
        Get-Content -Path $solutionsHtml | Add-Content -Path $indexHtml
        Get-Content -Path $footerHtml | Add-Content -Path $indexHtml
        if ($null -eq (Get-WebApplication -Name $AppName)) {
            $tooVerbose = New-WebVirtualDirectory -Site $iisConfig.SiteName -Name $VirtualDirectoryName -PhysicalPath $SolutionWebDir -Force
            $tooVerbose = New-WebApplication -Name $AppName  -Site "$($iisConfig.SiteName)\$VirtualDirectoryName" -PhysicalPath $SolutionWebDir -ApplicationPool $($iisConfig.applicationPool) -Force    
        }
    }
    function Update-MSEdgeAssociations {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $EdFiDir="C:\Ed-Fi",
            [string]$LogPath = "C:\Ed-Fi\Logs"
            )
        $AppAssocFile="$EdFiDir\LocalAppAssociations.xml"
        Start-Process -Wait Dism.exe "/Online /Export-DefaultAppAssociations:$AppAssocFile" -RedirectStandardOutput "$LogPath\dism-exp-log.txt" -RedirectStandardError "$LogPath\dism-exp-err.txt"
        $AppAssociations=New-Object XML
        $AppAssociations.Load($AppAssocFile)
        $AppSelections = $AppAssociations.SelectNodes("/DefaultAssociations/Association[@Identifier=""http"" or @Identifier=""https"" or @Identifier="".htm"" or @Identifier="".html""]")
        foreach ($node in $AppSelections) {
            $node.ProgID="MSEdgeHTM"
            $node.ApplicationName="Microsoft Edge"
        }
        $AppAssociations.save($AppAssocFile)
        Start-Process Dism.exe "/online /import-defaultappassociations:$AppAssocFile" -RedirectStandardOutput "$LogPath\dism-imp-log.txt" -RedirectStandardError "$LogPath\dism-imp-err.txt"
    }
    function Select-InstallPackages {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $globalPackages,
            $solutions,
            [Parameter(Mandatory)][ValidateSet('pre','post','db')][string]$sequence
        )
        # Empty list to start
        $packages=[System.Collections.Generic.List[PSCustomObject]]::new()
        # Determine whether global packages are an array of hashtables or just a space-separated string and convert or add
        if ($null -ne $globalPackages) {
            if ($globalPackages -is [string]) {
                if (! [string]::IsNullOrEmpty($globalPackages)) {
                    $pkgList=$globalPackages -split " "
                    foreach ($pkg in $pkgList) {
                        $packages.Add([PSCustomObject]@{package="$pkg"})
                    }
                }
            }
            else {
                if ($globalPackages -is [System.Collections.Generic.List[PSCustomObject]]) {
                    $packages.AddRange($globalPackages)
                }
                elseif ($globalPackages -is [array]) {
                    foreach ($pkg in $globalPackages) {
                        $packages.Add([PSCustomObject]$pkg)
                    }
                }
            }    
        }
        foreach ($sol in $solutions| Where-Object {$_.name -notlike "base*"} ) {
            switch ($sequence) {
                "pre" { $solPackages = $sol.preInstallPackages }
                "post" { $solPackages = $sol.postInstallPackages }
                "db" { $solPackages = $sol.dbInstallPackages }
            }
            if ($solPackages -is [string]) {
                if (! [string]::IsNullOrEmpty($solPackages)) {
                    $pkgList=$solPackages -split " "
                    foreach ($pkg in $pkgList) {
                        $packages.Add([PSCustomObject]@{package="$pkg"})
                    }
                }
            }
            elseif ($solPackages -is [array]) {
                foreach ($pkg in $solPackages) {
                    $packages.Add([PSCustomObject]$pkg)
                }
            }
            elseif ($solPackages -is [System.Collections.Generic.List[PSCustomObject]]) {
                $packages.AddRange($solPackages)
            }
        }
        if ($packages.Count -gt 0) {
            return $packages.ToArray()
        }
        else {
            return $null
        }
    }
    function Install-Solutions {
        [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
        param (
            $Solutions,
            $DnsName,
            $GitPrefix,
            $DownloadPath,
            $WebPath,
            $EdFiDir="C:\Ed-Fi"
            )
        # Ex: Install-Solutions -Solutions $solutionsInstall -DnsName $DnsName -GitPrefix $GitPrefix -DownloadPath $downloadPath -WebPath $SolutionsWebRoot -EdFiDir $EdFiDir
        if ([string]::IsNullOrEmpty($WebPath)) {
            $WebPath="$EdFiDir\www"
        }
        foreach ($sol in $Solutions) {
            if ($sol.name -like "base*") {
                $sol.name="Ed-Fi Solution Starter Kit base"
            }
            Write-Verbose "Installing $($sol.name)"
            if (!([string]::IsNullOrEmpty($sol.chocoPackages))) {
                Install-Choco $sol.chocoPackages -Verbose:$VerbosePreference
            }
            if (!([string]::IsNullOrEmpty($sol.repo))) {
                if (!($sol.repo -like "http*")) {
                    $repoURL="https://$($GitPrefix)@$($sol.repo)"
                }
                else {
                    $repoURL=$sol.repo
                }
                Write-Verbose "Cloning solution repo from: $repoURL"
                Set-Location $EdFiDir
                Copy-GitRepo $repoURL $sol.installSubPath  -Verbose:$VerbosePreference   # Installs in subdir of current dir
            }
            if (!([string]::IsNullOrEmpty($sol.archive))) {
                Write-Verbose "Downloading solution archive from: $($sol.archive) to $DownloadPath and extracting to $EdFiDir\$($sol.installSubPath)"
                Copy-WebArchive -Url $($sol.archive) -InstallPath "$EdFiDir\$($sol.installSubPath)" -DownloadsPath $DownloadPath -Verbose:$VerbosePreference
            }
            if(!(Test-Path -ErrorAction SilentlyContinue $sol.installSubPath)) {
                throw "Failed to install solution files! Check repo or archive settings`n Repo: $($sol.repo)`n Archive: $($sol.archive)"
            }
            if (!([string]::IsNullOrEmpty($sol.installer))) {
                # Pass in prefix and suffix to configure connections (db and API)
                & "$($sol.installSubPath)\$($sol.installer)" "Staging" $sol.EdFiVersion
            }
            foreach ($link in $sol.appLinks) {
                if ($link.type -eq "File") {
                    $link.URI = "$EdFiDir\$($sol.installSubPath)\$($link.URI)"
                }
                elseif (($link.type -eq "URL") -and !($link.URI -like "http*")) {
                    if ($link.URI -like "/*") {
                        $link.URI = $link.URI -Replace "^","https://$DnsName"
                    }
                    else {
                        $link.URI = $link.URI -Replace "^","https://$DnsName/"
                    }
                }
                elseif ($link.type -eq "App") {
                    $link.appfile = "$EdFiDir\$($sol.installSubPath)\$($link.appfile)"
                }
            }
            Add-DesktopAppLinks $sol.appLinks $sol.name -Verbose:$VerbosePreference
            # Add-WebAppLinks $sol.appLinks $sol.name $DnsName $SolutionWebRoot -Verbose:$VerbosePreference
            Add-WebAppLinks -AppURIs $sol.appLinks -DnsName $DnsName -SolutionName $sol.name -WebPath $WebPath -Verbose:$VerbosePreference
            Write-Verbose "Completed install of $($sol.name)"
        }
    }