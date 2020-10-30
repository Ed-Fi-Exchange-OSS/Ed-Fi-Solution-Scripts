# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
function Enable-TCPonSQLInstance {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ([string] $SQLINST = 'MSSQLSERVER') 
    #
    # Enable TCP on the default SQL instance.
    #
    Write-Verbose "Enabling TCP access for SQL Server instance: $SQLINST"
    $WMI = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer')
    # NEED to update and test with $SQLINST, hardcoded for now
    $URI = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='" + $SQLINST + "']/ServerProtocol[@Name='Tcp']"
    $TCPBinding = $WMI.GetSmoObject($URI)
    if ($TCPBinding.IsEnabled) { return }
    # Turn on by setting to true and Alter-ing
    $TCPBinding.IsEnabled = $true
    $TCPBinding.Alter()
}
function Set-WeakPasswordComplexity { 
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ([string] $FilePath="C:\Ed-Fi")
     # Verify that the file folder is present
     if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }  
    Write-Verbose "Allowing weak password complexity on Windows to prevent SQL Server from failing to login."
    # We have to disable password complexity so that SQL connections don't fail with default passwords
    # We need to set a strong password before re-enabling in Group Policy Editor 
    $secfile="$FilePath\secpol.cfg"
    $secdb="c:\windows\security\local.sdb"
    secedit /export /cfg $secfile
    (Get-Content $secfile).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File $secfile
    secedit /configure /db $secdb /cfg $secfile /areas SECURITYPOLICY
    Remove-Item -force $secfile -confirm:$false
}
function Install-SqlServerModule {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param()
    # This "global" prereq is needed even when the user has configured a postgres install
    # 
    # A check within the RestApi.Databases package used by Databases.psm1 mentions the SqlServer
    # module types prior to checking for "SqlServer" or "Postgres" engine mode. When database
    # installation packages adaquately deal with this prerequisite themselves, this can be removed.
    if (-not (Get-Module -ListAvailable -Name SqlServer -ErrorAction SilentlyContinue)) {
        Install-Module SqlServer -Force -AllowClobber -Confirm:$false
    }
    Import-Module SqlServer
    try {
        # Force it to use the right version
        (Get-Command Restore-SqlDatabase).ImplementingType.Assembly
    }
    catch {
        Write-Error "`nProblem loading correct SQL Server Management Objects.`n This will likely cause db restore to fail.`n  Error: $_ `n"
    }
}
function Add-SQLUser {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        $SQLServerName="."                              # Local machine by default
    )
    try {
        $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
        $SqlLogins = $SQLServer.Logins
        if ($SqlLogins.Count -lt 1) {
            Write-Error "Unable to read any SQL Server logins. Please check your access to the instance"
            return $false
        }
        if (!($SqlLogins.Contains($UserName))) {
            Write-Verbose "Adding Login for User: $UserName to SQL Server: $SQLServerName"
            $SqlUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SQLServer,$UserName
            $SqlUser.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsUser
            $SqlUser.PasswordPolicyEnforced = $false
            $SqlUser.Create()
            Write-Verbose "Added User: $UserName to Logins for SQL Server: $SQLServerName"
        }
        else {
            Write-Verbose "Login already exists for UserName:$UserName"
        }
    }
    catch {
        Write-Error "Failed to add user: $UserName to SQL Server: $SQLServerName`n`n Error: $_"
        return $false
    }
    return $true
}
function Update-SQLUser {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        [ValidateNotNullOrEmpty()][string]$OldUserName,
        $SQLServerName="."                      # Local machine by default
    )
    $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
    $SqlLogins = $SQLServer.Logins
    if ($SqlLogins.Count -lt 1) {
        throw "Unable to read any SQL Server logins. Please check your access to the instance"
    }
    $SqlUser = $SqlLogins | Where-Object { $_.name -like $UserName }
    if ($null -ne $sqlUser -and $SqlUser.Count -gt 0) {
        Write-Error "Attempting to rename UserName: $OldUserName is unable to complete because UserName: $UserName already in Logins."
        return $false
    }
    $SqlUser = $SqlLogins | Where-Object { $_.name -like $OldUserName }
    if ($null -ne $sqlUser -and $SqlUser.Count -gt 0) {
        try {
            Write-Verbose "Renaming previous UserName: $OldUserName to new UserName: $UserName on SQL Server: $SQLServerName"
            $SqlUser.Rename($NewName)
            Write-Verbose "Renamed User: $UserName for SQL Server: $SQLServerName"
        }
        catch {
            Write-Error "Failed to rename User: $OldUserName to $UserName on server: $SQLServerName`n  If you recently changed the host name, you may need to reboot first."
            return $false
        }
        return $true
    }
    else {
        Write-Verbose "UserName: $OldUserName not found in SQL Logins"
        return $false
    }
}
function Add-UserSQLRole {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string]$UserName,
        [string] $IntegratedSecurityRole = 'sysadmin',     # Should this be less powerful?
        [string] $SQLServerName = "."                      # Local machine by default
    )
    try {
        $SQLServer = New-Object Microsoft.SqlServer.Management.Smo.Server $SQLServerName
        Write-Verbose "Adding $UserName to $IntegratedSecurityRole on SQL Server: $SQLServerName"
        $serverRole = $SQLServer.Roles | Where-Object {$_.Name -eq $IntegratedSecurityRole}
        $serverRole.AddMember($UserName)
        Write-Verbose "Added User: $UserName to Role: $IntegratedSecurityRole for SQL Server: $SQLServerName"
    }
    catch {
        Write-Error "Failed to add user: $UserName to SQL Server role: $IntegratedSecurityRole on server: $SQLServerName`n`n Error: $_"
    }
}
function Add-SQLIntegratedSecurityUser {
    [CmdletBinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string] $UserName,
        [string] $IntegratedSecurityRole,
        [string] $SQLServerName
    )
    $success = Add-SQLUser -UserName $UserName -SQLServerName $SQLServerName -Verbose:$VerbosePreference
    Add-UserSQLRole -UserName $UserName -IntegratedSecurityRole $IntegratedSecurityRole -SQLServerName $SQLServerName -Verbose:$VerbosePreference
}
function Update-SQLIntegratedSecurityUser {
    [CmdletBinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [ValidateNotNullOrEmpty()][string] $UserName,
        [ValidateNotNullOrEmpty()][string] $ComputerName,
        [ValidateNotNullOrEmpty()][string] $PreviousComputerName,
        [string] $IntegratedSecurityRole,
        [string] $SQLServerName = "."
    )
    Write-Verbose "Updating UserName:$UserName from: $PreviousComputerName to: $ComputerName"
    if (!($ComputerName -like $PreviousComputerName) -and ($UserName -like "$PreviousComputerName\*")) {
        Write-Warning "Username: $UserName includes previous computer name:$PreviousComputerName `n   Removing computer name from user name"
        $UserName=$UserName -Replace "$PreviousComputerName\\(?<user>.*)",'${user}'
        Write-Warning " !!  Changing the hostname and SQL Server logins will require the system to be rebooted before initial use.  !!"
    }
    if ((!($UserName -like "$ComputerName\*")) -and ($UserName -like "*\*")) {
        Write-Error "UserName: $UserName includes a different domain than the computer name. `n   Cmdlet will not attempt to rename domain users."
    }
    else {
        $success=$false
        if (!($ComputerName -like $PreviousComputerName)) {
            $NewName = $UserName
            if ($UserName -like "$ComputerName\*") {
                $JustName = $Username -Replace "$ComputerName\\(?<user>.*)",'${user}'
                $OldName = "$PreviousComputerName\$JustName"
            }
            else {
                $OldName = "$PreviousComputerName\$UserName"
                $NewName = "$ComputerName\$UserName"
            }
            if (!($NewName -like $OldName)) {
                Write-Verbose "Updating UserName:$OldName to UserName:$NewName on server:$SQLServerName"
                $success = Update-SQLUser -UserName $NewName -OldUserName $OldName -SQLServerName $SQLServerName -Verbose:$VerbosePreference    
            }    
        }
        if (!$success) {
            Write-Verbose "Adding UserName:$UserName to server:$SQLServerName"
            $success = Add-SQLUser -UserName $UserName -SQLServerName $SQLServerName -Verbose:$VerbosePreference
        }
    }
    Add-UserSQLRole -UserName $UserName -IntegratedSecurityRole $IntegratedSecurityRole -SQLServerName $SQLServerName -Verbose:$VerbosePreference
}
function Get-MSSQLInstallation {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()
    if (Test-Path -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        $sqlInstances = Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names"
        Write-Verbose "SQL Server installation found with instances:`n $($sqlInstances|ForEach-Object {$_.Property}) `n"
        # Get SQL Server PowerShell support from the PS Gallery
        Install-SqlServerModule -Verbose:$VerbosePreference
        # Ensure TCP Connectivity is enabled
        $SQLINST=$sqlInstances[0].Property[0]
        Enable-TCPonSQLInstance -SQLINST $SQLINST -Verbose:$VerbosePreference
        return $SQLINST
    }
    return $null
}
function Install-MSSQLserverExpress {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $FilePath="C:\Ed-Fi\Downloads",
        [string] $MSSQLEURL="https://download.microsoft.com/download/8/4/c/84c6c430-e0f5-476d-bf43-eaaa222a72e0/SQLEXPR_x64_ENU.exe",
        [string] $SQLINST="MSSQLSERVER"
    )
    # Verify that the file folder is present
    if (! $(try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false })) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }
    #
    # Check for existing installation
    $ExistingSQLINST=Get-MSSQLInstallation
    if (![string]::IsNullOrEmpty($ExistingSQLINST)) {
        return $ExistingSQLINST
    }
    # No SQL instances found so we'll Install MS SQL Server Express 2019 with our special install config ini file
    #
    $InstINI = "$FilePath\SQLExprConfig.ini"
    # First try Chocolatey
    Install-Choco -Packages "sql-server-express" -InstallArguments "/ACTION=install /Q /IACCEPTSQLSERVERLICENSETERMS /INSTANCEID=MSSQLSERVER /INSTANCENAME=MSSQLSERVER /ConfigurationFile=$InstINI"
    $ExistingSQLINST=Get-MSSQLInstallation
    if (![string]::IsNullOrEmpty($ExistingSQLINST)) {
        return $ExistingSQLINST
    }
    Write-Verbose "SQL Server Express installation by Chocolatey failed.  Attempting to download and install directly."
    #
    $MSSEFILE = "$FilePath\SQLEXPR_x64_ENU.exe"
    $MSSEPATH = "$FilePath\SQLEXPR_x64_ENU"
    $MSSESETUP = "$MSSEPATH\setup.exe"
    # Download, unpack, and install while setting the default instance name - will probably need to periodically refreshed until choco install works 
    if (! $(try { Test-Path -ErrorAction SilentlyContinue $MSSEFILE } Catch { $false }) ) {
        try {
            Write-Verbose "Downloading $MSSQLEURL to $MSSEFILE"
            Write-Progress -Activity "Downloading SQL Server Express" -Status "1% Complete:" -PercentComplete 1;
            Invoke-WebRequest -Uri $MSSQLEURL -OutFile $MSSEFILE
        }
        catch {
            Write-Error "Failed to download SQL Server Express from $MSSQLEURL and store in $MSSEFILE  Check URL and permission on path.  Error: $_"
        }
    }
    if ( $(try { Test-Path -ErrorAction SilentlyContinue $MSSEFILE } Catch { $false } ) ) {
        if (! $(Try { Test-Path -ErrorAction SilentlyContinue  $MSSESETUP } Catch { $false } ) ) {
            Write-Verbose "  Start-Process $MSSEFILE -wait -ArgumentList `"/q`",`"/x:$MSSEPATH`" -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt"
            Write-Progress -Activity "Decompressing SQL Server Express install package" -Status "30% Complete:" -PercentComplete 30;
            Start-Process $MSSEFILE -wait -ArgumentList "/q","/x:$MSSEPATH" -RedirectStandardOutput $MSSEPATH\extract_log.txt -RedirectStandardError $MSSEPATH\extract_error_log.txt
        }
    }
    if ($(Try { Test-Path -ErrorAction SilentlyContinue $MSSESETUP } Catch { $false })) {
        Write-Verbose " Start-Process $MSSESETUP -wait -WorkingDirectory $MSSEPATH -RedirectStandardOutput $MSSEPATH\setup_log.txt -RedirectStandardError $MSSEPATH\setup_error_log.txt -ArgumentList `"/IACCEPTSQLSERVERLICENSETERMS`",`"/Q`",`"/INSTANCEID=$SQLINST`",`"/INSTANCENAME=$SQLINST`",`"/ConfigurationFile=$InstINI`""
        Write-Progress -Activity "Installing SQL Server Express" -Status "60% Complete:" -PercentComplete 60;
        Start-Process $MSSESETUP -wait -ArgumentList "/IACCEPTSQLSERVERLICENSETERMS","/Q","/INSTANCEID=$SQLINST","/INSTANCENAME=$SQLINST","/ConfigurationFile=$InstINI" -WorkingDirectory $MSSEPATH -RedirectStandardOutput $MSSEPATH\setup_log.txt -RedirectStandardError $MSSEPATH\setup_error_log.txt
    }

    if (!(Test-Path -ErrorAction SilentlyContinue "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")) {
        throw "SQL Server failed to install, installation canceled" 
    }
    #
    Write-Progress -Activity "SQL Server Express installed" -Status "80% Complete:" -PercentComplete 80;
    Update-SessionEnvironment
    #
    Write-Progress -Activity "Installing PowerShell modules for SQL Server" -Status "85% Complete:" -PercentComplete 85;
    Install-SqlServerModule
    #
    # Use freshly installed MS SQL Server
    Write-Progress -Activity "Enabling TCP on default SQL Server instance" -Status "95% Complete:" -PercentComplete 95;
    Enable-TCPonSQLInstance -SQLINST $SQLINST
    return $SQLINST
}
function Initialize-Postgresql {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param ()   
    #
    # Check the Postgres install
    $psqlHome=Get-Command "psql.exe" -ErrorAction SilentlyContinue | ForEach-Object {$_.Source -Replace "\\bin\\psql.exe", ""}
    if (!$psqlHome) {
        $psqlInstall = Get-ChildItem -Path "C:\Program Files\PostgreSQL\*" -ErrorAction SilentlyContinue | Sort-Object -Property @{expression='Name'; descending=$true}
        if (!$psqlInstall) {
            Install-Choco "postgresql"
            $psqlInstall = Get-ChildItem -Path "C:\Program Files\PostgreSQL\*" | Sort-Object -Property @{expression='Name'; descending=$true}
        }
        $psqlHome = "C:\Program Files\PostgreSQL\" + $psqlInstall.Name
    }

    if (-not (Test-Path -ErrorAction SilentlyContinue $psqlHome)) {
        throw "Required Postgres path not found: $psqlHome"
    }

    Write-Verbose "Prepending $psqlHome to the PATH."
    $env:Path = "$psqlHome\bin;" + $env:Path
    if (!$Env:PGDATA) { $Env:PGDATA = $psqlHome + "\data" }
    if (!$Env:PGLOCALEDIR) { $Env:PGLOCALEDIR = $psqlHome + "\share\locale" }
    if (!$Env:PGPORT) { $Env:PGPORT = "5432" }
}
