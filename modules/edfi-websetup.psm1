# SPDX-License-Identifier: Apache-2.0
# Licensed to the Ed-Fi Alliance under one or more agreements.
# The Ed-Fi Alliance licenses this file to you under the Apache License, Version 2.0.
# See the LICENSE and NOTICES files in the project root for more information.
function Get-SelfSignedCertificate {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        [string] $CertName="localhost Self-Signed",
        [string] $FilePath="C:\Ed-Fi"
    )
    # Verify that the file folder is present
    if (! $(Try { Test-Path -ErrorAction SilentlyContinue $FilePath } Catch { $false }) ) {
        $tooVerbose = New-Item -ItemType Directory -Force -Path $FilePath
    }    
    # Returns the Certificate Thumbprint if successful
    # Stores Self-Signed Cert in Cert:\LocalMachine\My and then in Cert:\LocalMachine\Root to avoid problems with invalid cert chains
    # See if we already have it installed.
    $certificates = Get-ChildItem Cert:\LocalMachine\My
    foreach($cert in $certificates) {
        if ($cert.FriendlyName -eq $CertName) { 
            Write-Verbose "Found Self-Signed Cert Thumbprint: $($cert.Thumbprint)"
            return $cert
        }
    }
    #Create self signed certificate
    $hostnames = @("localhost")
    if (!([string]::IsNullOrEmpty($DnsName) -or ($DnsName -eq "localhost"))) {
        $hostnames += $DnsName
    }
    $cert = New-SelfSignedCertificate -DnsName $hostnames -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName $CertName -NotAfter $((Get-Date).AddYears(10)) -KeyExportPolicy 'Exportable' -KeyFriendlyName $CertName -KeyDescription "Self-signed certificate for localhost"
    $rootStore = new-object system.security.cryptography.X509Certificates.X509Store -argumentlist "Root", LocalMachine
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]"ReadWrite")
    $rootStore.Add($cert)
    Write-Verbose "Created Self-Signed Cert with Thumbprint: $($cert.Thumbprint)"
    return $cert
}
function Get-LetsEncSSLCert {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $DnsName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $AdminEmail="techsupport@ed-fi.org",
        $CertName="Ed-Fi Solution Installer",
        [string]$LogPath = "C:\Ed-Fi\Logs"
    )
    # Check for existing certificate first
    $certificates = Get-ChildItem Cert:\LocalMachine\WebHosting
    foreach($cert in $certificates) { 
        if($cert.Subject -eq "CN=$DnsName") { 
            $cert.FriendlyName=$CertName
            Write-Verbose "Found SSL Cert for $DnsName with Thumbprint: $($cert.Thumbprint)"
            return $cert
        } 
    }
    if (!(Get-Command "wacs" -ErrorAction SilentlyContinue)) {
        Install-Choco "win-acme"
    }
    try {
        # The Win-Acme client will do all of the work of calling the API, storing the certificate,
        # and adding it to the matching host entry in IIS
        Start-Process "wacs" -Wait -ArgumentList "--target iis --host $DnsName --accepttos --emailaddress $AdminEmail" -RedirectStandardOutput "$LogPath\winacme_ssl_cert_log.txt" -RedirectStandardError "$LogPath\winacme_ssl_cert_err.txt"
        Write-Verbose "Windows Acme Client Services completed SSL certificate request.`nCheck WACS log files for more info:`nwinacme_ssl_cert_log.txt`nwinacme_ssl_cert_err.txt"
    }
    catch {
        Write-Error "WACS failed to generate a certifcate from Lets Encrypt.  Error: $_ "
        return $null
    }
    $certificates = Get-ChildItem Cert:\LocalMachine\WebHosting
    if ($null -eq $certificates) {
        return $null
    }
    foreach($cert in $certificates) { 
        Write-Verbose "Found SSL Cert with Thumbprint: $($cert.Thumbprint)"
        if($cert.Subject -eq "CN=$DnsName") { 
            $cert.FriendlyName=$CertName
            Write-Verbose "Generated SSL Cert for $DnsName with Thumbprint: $($cert.Thumbprint)"
            return $cert
        }
    }
    return $null
}
function Get-SiteSSLCertificate {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        $iisConfig = @{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; SiteName="Ed-Fi"; defaultApplicationPool = "DefaultAppPool"; applicationPool = "EdFiAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $defaultSiteName = $iisConfig.defaultSiteName
    $SiteName = $iisConfig.SiteName
    $httpsBinding = $null
    if ([string]::IsNullOrEmpty($DnsName) -or ($DnsName -like "localhost*")) {
        $DnsName = "localhost"
    }
    # Check for a different Site Name than default
    if ([string]::IsNullOrEmpty($SiteName)) {
        # Must use default site name on localhost to avoid breaking things
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Look for and return an existing SSL binding for the given site name
    try {
        if ($httpsBinding=Get-IISSiteBinding -Name $SiteName -Protocol "https") {
            return $httpsBinding.CertificateHash
        }    
    }
    catch {
        Write-Verbose "`nIIS not yet configured for https on $SiteName `n"
        return $null
    }
}
function Set-IISHttpBinding {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $DnsName,
        $SiteName="Ed-Fi"
    )
    $iisSrvMgr = Get-IISServerManager
    $httpBinding=$null
    try {
        $httpBinding=Get-IISSiteBinding -Name $SiteName -BindingInformation "*:80:$DnsName"  -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "No binding for host:$DnsName for site:$SiteName `n  Attempting to bind."
    }
    if ($null -eq $httpBinding) {
        try {
            Start-IISCommitDelay
            Write-Verbose "Command:`n New-IISSiteBinding -name `"$SiteName`" -BindingInformation `"*:80:$DnsName`" -protocol http`n"
            $httpBinding = New-IISSiteBinding -name $SiteName -BindingInformation "*:80:$DnsName" -protocol "http"
            $iisSrvMgr.CommitChanges()
            Stop-IISCommitDelay
        }
        catch {
            Write-Warning "Warning:`n Failed to set IIS binding for $DnsName on http.`n  Exception was: $_ `n"
        }
    }
    return $httpBinding
}
function Set-IISSslBinding {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        $DnsName,
        $HttpsPort="443",
        $SiteName="Ed-Fi",
        $SslCertificate,
        $certStoreLocation = "Cert:\LocalMachine\WebHosting",
        $certStoreName = "WebHosting"
    )
    $httpsBinding=$null
    #
    # Configure IIS to use Lets Encrypt SSL Cert or Self-Signed, if needed
    #
    $isLocal=$false
    # In case you passed in some variant of localhost somehow, we'll switch to self-signed certs.
    if ([string]::IsNullOrEmpty($DnsName)-or($DnsName -like "localhost*")-or($DnsName -eq "*")) {
        $certStoreLocation = "Cert:\LocalMachine\My"
        $certStoreName = "MY"
        $isLocal=$true
    }
    else {
        # Check to see if a name-specific binding already exists and set one if not.
        # This helps the Acme client since it prefers a binding for a specific host name, and it shouldn't break a wildcard entry.
        $httpBinding=Set-IISHttpBinding -DnsName $DnsName -SiteName $SiteName
        if ($null -eq $httpBinding) {
            Write-Warning "Unable to set http mapping for $DnsName. This may result in failures for certificate renewals for Let's Encrypt ACME client."
        }
    }
    try {
        $allBindings=Get-IISSiteBinding -Name $SiteName -Protocol "https" | Where-Object {$_.BindingInformation -like "*:${HttpsPort}:*" }
        Write-Verbose "Existing bindings for site: $SiteName`n  $allBindings"
    }
    catch {
        Write-Verbose "No bindings for IIS Site: $SiteName on https port: $HttpsPort"
    }
    # Look for and return an existing SSL binding for the given site name, or * if found
    if ($null -ne $allBindings) {
        $httpsBinding=$allBindings | Where-Object {$_.BindingInformation -like "*$DnsName"}
        if ($null -eq $httpsBinding) {
            $httpsBinding=$allBindings | Where-Object {$_.BindingInformation -eq "*:${HttpsPort}:*"}
            if ($null -ne $httpsBinding) {
                Write-Warning "Using existing wilcard (*) binding on hostname.`n  If cert is not wilcard or subject alt names don't cover actual mappings, site will have certificate errors."
                $isLocal=$true
            }
        }
    }
    if ($null -ne $httpsBinding) {
        try {
            $iisSrvMgr = Get-IISServerManager
            Start-IISCommitDelay
            Write-Warning "Changing cert store and thumprint for existing binding.`nSite: $SiteName Binding: *:${HttpsPort}:$DnsName Cert store:$certStoreLocation Hash/Thumprint: $($SslCertificate.Thumbprint)"
            $httpsBinding.CertificateStoreName=$certStoreName
            $httpsBinding.CertificateHash=$SslCertificate.Thumbprint
            $iisSrvMgr.CommitChanges()
            Stop-IISCommitDelay
        }
        catch {
            throw "Failed to set certstorename: $certStoreName and certificateHash: $($SslCertificate.Thumbprint) for site binding: $httpsBinding"
        }
    }
    else {
        if (($null -ne $allBindings)-and($DnsName -notlike "*localhost*")) {
            try {
                $iisSrvMgr = Get-IISServerManager
                Start-IISCommitDelay
                Write-Warning "There are other SSL bindings on port $HttpsPort for this website for hosts other than $DnsName.`n  Updating these bindings to use Server Name Ident so that they can coexist."
                foreach ($bnd in $allBindings) {
                    # Add SNI for this name
                    # For use by Netsh
                    # $appguid = [guid]::NewGuid().ToString("B")
                    # $netshCmd = (Get-Command "netsh.exe").Source
                    # & $netshCmd http add sslcert hostnameport="$($bnd.Host):$HttpsPort" certhash=$bnd.CertificateHash certstorename=$bnd.CertificateStoreName appid="$appguid"
                    if (($bnd.SslFlags -like "*CentralCertStore*")-or($bnd.SslFlags -gt 1)) {
                        $bnd.SslFlags=3
                    }
                    else {
                        $bnd.SslFlags=1
                    }
                }
                $sm.CommitChanges()
                Stop-IISCommitDelay            
            }
            catch {
                Write-Warning "Failed to set SslFlags for bindings on site: $SiteName  Attempting to continue anyway. `n Error: $_"
            }
        }
        if (!$isLocal) {
            try {
                $iisSrvMgr = Get-IISServerManager
                Start-IISCommitDelay
                # Now add binding finally, setting Sni flag
                Write-Verbose "Command:`n New-IISSiteBinding -name $SiteName -BindingInformation `"*:${HttpsPort}:$DnsName`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($SslCertificate.Thumbprint)`" -SslFlag `"Sni`"`n"
                $httpsBinding = New-IISSiteBinding -name $SiteName -BindingInformation "*:${HttpsPort}:$DnsName" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint $($SslCertificate.Thumbprint) -SslFlag "Sni"
                $iisSrvMgr.CommitChanges()
                Stop-IISCommitDelay
#                Write-Verbose "Command: $netshCmd http add sslcert hostnameport=`"${DnsName}:$HttpsPort`" certhash=$certHash certstorename=$certStoreName appid=`"$appguid`""
#                & $netshCmd http add sslcert hostnameport="${DnsName}:$HttpsPort" certhash=$certHash certstorename=$certStoreName appid="$appguid"
            }
            catch {
                Write-Error "Failed to bind https on port $HttpsPort to host $DnsName for site: $SiteName"
                Write-Error "Error:$_"
            }
        }
        else {
            try {
                $iisSrvMgr = Get-IISServerManager
                Start-IISCommitDelay
                # Add binding but no SSL flags
                Write-Verbose "Command:`n New-IISSiteBinding -name $SiteName -BindingInformation `"*:${HttpsPort}:$DnsName`" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint `"$($SslCertificate.Thumbprint)`" -SslFlag `"Sni`"`n"
                $httpsBinding = New-IISSiteBinding -name $SiteName -BindingInformation "*:${HttpsPort}:$DnsName" -protocol https -CertStoreLocation $certStoreLocation -CertificateThumbPrint $($SslCertificate.Thumbprint) -SslFlag "Sni"
                $iisSrvMgr.CommitChanges()
                Stop-IISCommitDelay
            }
            catch {
                Write-Error "Error while binding IIS Site: $SiteName on https with binding: *:${HttpsPort}:$DnsName with Certificate: $($SslCertificate.Thumbprint) .`n Error: $_"
            }
        }
    }
    return $httpsBinding
}
function Set-IISSiteName {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $InstallPath,
        [string] $DnsName,
        $iisConfig = @{defaultSiteName="Default Web Site"; SiteName="Ed-Fi"; defaultApplicationPool = "DefaultAppPool"; applicationPool = "EdFiAppPool"}
    )
    $iisSite=$null
    $defaultSiteName=$iisConfig.defaultSiteName
    $SiteName=$iisConfig.SiteName
    $newAppPool=$iisConfig.applicationPool
    while ($null -eq $iisSite) {
        try {
            $iisSite=Get-IISSite $SiteName
        }
        catch {
            Write-Error "Error with Get-IISSite: $_"
        }
        if ($null -eq $iisSite) {
            Write-Verbose "Site Name: $SiteName not found.`n  Creating new IIS Site."
            try {
                $iisSrvMgr = Get-IISServerManager
                Start-IISCommitDelay
                if ([string]::IsNullOrEmpty($newAppPool)) {
                    $newAppPool = "$SiteName-AppPool"
                }
                $newAppPool = $newAppPool -replace "\W"  # Nothing but alphanumerics in this name
                Write-Verbose "Creating site '$SiteName' with default app pool '$newAppPool'"
                $iisSrvMgr.ApplicationPools.Add($newAppPool)
                Write-Verbose "New-IISSite -Name $SiteName -BindingInformation `"*:80:$DnsName`" -PhysicalPath `"$InstallPath\www`""
                $iisSite=New-IISSite -Name $SiteName -BindingInformation "*:80:$DnsName" -PhysicalPath "$InstallPath\www"
                Write-Verbose "Setting default AppPool for IIS Site: $SiteName to AppPool: $newAppPool"
                $iisSrvMgr.Sites[$SiteName].Applications["/"].ApplicationPoolName = $newAppPool
                $iisSrvMgr.CommitChanges()
                Stop-IISCommitDelay
            }
            catch {
                Stop-IISCommitDelay
                if ($SiteName -eq $defaultSiteName) {
                    throw "No IIS default site: $defaultSiteName `n  Unable to configure IIS for HTTP or HTTPS." 
                }
                Write-Warning "Unable to create IIS Site Name: $SiteName `n  Switching to default site name: $defaultSiteName and trying again."
                $SiteName=$defaultSiteName
                $iisSite=$null
            }
        }
        else {
            Write-Verbose "Found existing IIS Site named: $SiteName at:$iisSite"
        }
    }
    return $iisSite
}
function Enable-WebServerSSL {
    [cmdletbinding(HelpUri="https://github.com/Ed-Fi-Exchange-OSS/Ed-Fi-Solution-Scripts")]
    param (
        [string] $InstallPath,
        [string] $HostDNS,
        [string] $HttpsPort="443",
        [string] $AdminEmail = 'techsupport@ed-fi.org',
        $iisConfig = @{ iisUser="IIS_IUSRS"; defaultSiteName="Default Web Site"; SiteName="Ed-Fi"; defaultApplicationPool = "DefaultAppPool"; applicationPool = "EdFiAppPool"; integratedSecurityUser = "IIS APPPOOL\DefaultAppPool" }
    )
    $defaultSiteName = $iisConfig.defaultSiteName
    $SiteName = $iisConfig.SiteName
    $iisSite = $null
    $httpsBinding = $null
    Set-Location $InstallPath    
    if ([string]::IsNullOrEmpty($HostDNS) -or ($HostDNS -like "localhost*")) {
        $HostDNS = "localhost"
        # Must use default site name on localhost to avoid breaking things
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Check for a different Site Name than default
    if ([string]::IsNullOrEmpty($SiteName)) {
        $SiteName = $defaultSiteName
        Write-Verbose "Using default (existing) IIS site: $SiteName"
    }
    # Look for and return an existing SSL binding for the given site name
    try {
        if ($httpsBinding=Get-IISSiteBinding -Name $SiteName -Protocol "https" -BindingInformation "*:${HttpsPort}:$HostDNS" -ErrorAction SilentlyContinue) {
            Write-Verbose "`nIIS is already configured for https on $SiteName for DNS: $HostDNS on port: $HttpsPort as binding: $httpsBinding.`n  Quitting without changing SSL for IIS.`n"
            return $SiteName
        }    
    }
    catch {
        Write-Verbose "`nIIS not yet configured for https on $SiteName for DNS: $HostDNS`n  Checking for wilcard entry.`n"
    }
    try {
        if ($httpsBinding=Get-IISSiteBinding -Name $SiteName -Protocol "https" -BindingInformation "*:${HttpsPort}:*" -ErrorAction SilentlyContinue) {
            Write-Warning "`nIIS is already configured for https on $SiteName for the all-hosts wildcard (*) on port: $HttpsPort as binding: $httpsBinding.`n  Changing the SSL certificate for the wildcard anyway.`n  This will break SSL validity for certain hostnames such as localhost"
        }
    }
    catch {
        Write-Verbose "`nIIS not yet configured for https on $SiteName `n  Checking for IIS Site first.`n"
    }
    # Delay writing updates until we are done
    # Get/Set IIS site name
    $iisSite = Set-IISSiteName -InstallPath $InstallPath -DnsName $HostDNS -iisConfig $iisConfig
    #
    # Configure IIS to use Lets Encrypt SSL Cert or Self-Signed, if needed
    #
    # Get self-signed certificate for localhost needs
    $selfSignedCert = Get-SelfSignedCertificate -DnsName $HostDNS -CertName "localhost Self-Signed" -FilePath $InstallPath -Verbose:$VerbosePreference
    $httpBinding=$null
    $newCert=$null
    # In case you passed in some variant of localhost somehow, don't go tryin to create a cert for that, not even a little bit.
    if ($HostDNS -like "localhost") {
        $httpsLHBinding=Set-IISSslBinding -DnsName $HostDNS -SslCertificate $selfSignedCert -HttpsPort $HttpsPort -SiteName $SiteName -certStoreName "MY" -certStoreLocation "Cert:\LocalMachine\My" -Verbose:$VerbosePreference
        $httpsBinding=$httpsLHBinding
    }
    else {
        # If missing, add a binding to the given hostname in case the system does not recognize that name as being local yet .. to make sure the Acme client will work
        #  and it shouldn't break the usual wildcard entry 
        $httpBinding=Set-IISHttpBinding -DnsName $HostDNS -SiteName $SiteName -Verbose:$VerbosePreference
        # Obtain a free Let's Encrypt cert for given hostname
        $newCert = Get-LetsEncSSLCert -DnsName $HostDNS -CertName "Ed-Fi Solution Installer" -AdminEmail $AdminEmail -Verbose:$VerbosePreference
        if ($null -eq $newCert) {
            Write-Warning "Failed to get Let's Encrypt cert, binding self-signed cert to wildcard instead"
            $httpsBinding=Set-IISSslBinding -DnsName "*" -SslCertificate $selfSignedCert -HttpsPort $HttpsPort -SiteName $SiteName -certStoreName "MY" -certStoreLocation "Cert:\LocalMachine\My" -Verbose:$VerbosePreference
        }
        else {
            $httpsBinding=Set-IISSslBinding -DnsName $HostDNS -SslCertificate $newCert -HttpsPort $HttpsPort -SiteName $SiteName -certStoreName "WebHosting" -certStoreLocation "Cert:\LocalMachine\WebHosting" -Verbose:$VerbosePreference
            #
            # Add SPN for new DNS entry so that the IIS Server can support Windows Auth on that domain name
            # $spnCmd = Get-Command "setspn.exe"
            # if ($null -ne $spnCmd) {
            #     & $spnCmd "-A HTTP/$HostDNS" # add $iisConfig.integratedSecurityUser for AD use
            # }
            #
            # Attaching the self-signed certificate to localhost
            $httpsLHBinding=Set-IISSslBinding -DnsName "localhost" -SslCertificate $selfSignedCert -HttpsPort $HttpsPort -SiteName $SiteName -certStoreName "MY" -certStoreLocation "Cert:\LocalMachine\My" -Verbose:$VerbosePreference
        }
    }
    Write-Verbose "IIS is configured for https on $SiteName as $httpsBinding`n "
    return $SiteName
}