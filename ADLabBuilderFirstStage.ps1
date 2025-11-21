<#
    AutoDC_Configuration.ps1

    DESCRIPTION:
    This script prepares a Windows Server for automated Active Directory deployment.
    It interactively asks for:
      * Domain name / FQDN
      * Whether to use DHCP or a static IP
      * Optional static IP configuration
      * Optional auto-login (lab use only)
    Then it installs AD DS, DNS, and promotes the server to a new forest.

    INSTRUCTIONS:
    1. Run this script as Administrator on a clean Windows Server machine.
    2. Follow the prompts in the console.
    3. The server will reboot automatically after promotion.

    AUTHOR: MrOlof
#>

# ================================
# SECTION 0: Helper Functions
# ================================

function Read-YesNo {
    param(
        [string]$Message,
        [string]$Default = 'Y'
    )

    while ($true) {
        $prompt = if ($Default -eq 'Y') { "$Message [Y/n]: " } else { "$Message [y/N]: " }
        $resp = Read-Host -Prompt $prompt

        if ([string]::IsNullOrWhiteSpace($resp)) {
            $resp = $Default
        }

        switch ($resp.ToUpper()) {
            'Y' { return $true }
            'N' { return $false }
            default { Write-Host "Please answer Y or N." -ForegroundColor Yellow }
        }
    }
}

function Get-NonEmptyInput {
    param(
        [string]$Message,
        [string]$Default = $null
    )

    while ($true) {
        if ($null -ne $Default -and $Default -ne '') {
            $value = Read-Host "$Message [$Default]"
            if ([string]::IsNullOrWhiteSpace($value)) {
                return $Default
            }
        }
        else {
            $value = Read-Host $Message
            if ([string]::IsNullOrWhiteSpace($value)) {
                Write-Host "Value cannot be empty." -ForegroundColor Yellow
                continue
            }
        }

        return $value
    }
}

# ================================
# SECTION 1: Interactive Setup
# ================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      Welcome to AD Lab Builder"            -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# --- Domain configuration ---

# Ask for FQDN (e.g. lab.local)
$FQDN = Get-NonEmptyInput -Message "Enter the AD domain FQDN (for example: lab.local)"

# Derive short name / NetBIOS from FQDN
$DefaultShortName = ($FQDN.Split('.')[0]).ToUpper()
if ($DefaultShortName.Length -gt 15) {
    $DefaultShortName = $DefaultShortName.Substring(0,15)
}

$DomainName  = Get-NonEmptyInput -Message "Enter the NetBIOS/short domain name" -Default $DefaultShortName
$NetbiosName = $DomainName  # keep them aligned for this lab

Write-Host ""
Write-Host "Domain configuration:" -ForegroundColor Cyan
Write-Host "  FQDN:       $FQDN"
Write-Host "  NetBIOS:    $NetbiosName"
Write-Host ""

# --- Password configuration ---

Write-Host "The next password will be used for:" -ForegroundColor Cyan
Write-Host "  * DSRM (Directory Services Restore Mode) admin password" 
Write-Host "  * Optional auto-login (if you enable it later)" 
Write-Host ""
$PlainPassword = Get-NonEmptyInput -Message "Enter the Administrator / DSRM password"

# Secure version for ADDS
$SafeModeSecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

# Local admin to use for auto-login (if enabled)
$AutoLoginUser = "Administrator"

# --- Network adapter detection ---

$InterfaceAlias = (Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and
    $_.InterfaceDescription -notmatch 'Loopback|Virtual'
} | Select-Object -First 1).Name

Write-Host ""
Write-Host "Detected active network adapter: $InterfaceAlias" -ForegroundColor Cyan
Write-Host ""

# ================================
# SECTION 2: Network Configuration (DHCP or Static)
# ================================

Write-Host "Network configuration" -ForegroundColor Cyan
Write-Host "For most first-time lab setups, using DHCP is perfectly fine."
Write-Host ""

$UseStaticIP = Read-YesNo -Message "Do you want to configure a STATIC IP address? (Recommended only if you know your network)" -Default 'N'

$IPAddress    = $null
$PrefixLength = $null
$Gateway      = $null
$DNSServers   = $null

if ($UseStaticIP) {
    Write-Host ""
    Write-Host "Enter static IP settings. Press Enter to accept defaults if shown." -ForegroundColor Cyan

    # Provide sane defaults based on a typical lab, user can override
    $IPAddress    = Get-NonEmptyInput -Message "Static IP address"           -Default "192.168.12.10"
    $PrefixLength = Get-NonEmptyInput -Message "Prefix length (e.g. 24)"     -Default "24"
    $Gateway      = Get-NonEmptyInput -Message "Default gateway"             -Default "192.168.12.1"
    $DNSServers   = Get-NonEmptyInput -Message "DNS server(s) (comma list)"  -Default "127.0.0.1"

    Write-Host ""
    Write-Host "Applying static IP configuration..." -ForegroundColor Cyan
    try {
        # Clear any existing IPs on that adapter (best-effort, ignore errors)
        Get-NetIPAddress -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue | `
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress -InterfaceAlias $InterfaceAlias `
                         -IPAddress $IPAddress `
                         -PrefixLength ([int]$PrefixLength) `
                         -DefaultGateway $Gateway

        $dnsArray = $DNSServers.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $dnsArray

        Write-Host "Static IP $IPAddress configured successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to configure static IP. Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Continuing with existing network settings (likely DHCP)." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Keeping existing network configuration (DHCP / current settings)." -ForegroundColor Green
}

# ================================
# SECTION 3: Optional Auto-Login
# ================================

Write-Host ""
Write-Host "Auto-login configuration (LAB ONLY!)" -ForegroundColor Cyan
Write-Host "This will store the Administrator password in clear text in the registry." -ForegroundColor Yellow
Write-Host "That is fine for an isolated lab, but NEVER do this in production." -ForegroundColor Yellow
Write-Host ""

$ConfigureAutoLogin = Read-YesNo -Message "Do you want to enable auto-login with the local Administrator account?" -Default 'N'

if ($ConfigureAutoLogin) {
    Write-Host "`nConfiguring auto-login for next boot..." -ForegroundColor Cyan

    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon"    -Value "1"            -Type String
    Set-ItemProperty -Path $RegPath -Name "DefaultUsername"   -Value $AutoLoginUser -Type String
    Set-ItemProperty -Path $RegPath -Name "DefaultPassword"   -Value $PlainPassword -Type String
    Set-ItemProperty -Path $RegPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME -Type String

    Write-Host "Auto-login configured for user '$AutoLoginUser' on this machine." -ForegroundColor Green

    <#
    # OPTIONAL: If you want to automatically run another script after first login,
    # uncomment and adjust this RunOnce block.

    Write-Host "Scheduling follow-up deployment script to run on first login..." -ForegroundColor Cyan

    $RunOncePath      = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $DeploymentScript = "C:\Scripts\AutoDC-Deployment.ps1"  # Adjust path if needed
    $Command          = "powershell.exe -ExecutionPolicy Bypass -File `"$DeploymentScript`""

    Set-ItemProperty -Path $RunOncePath -Name "RunADLabFollowup" -Value $Command

    Write-Host "RunOnce follow-up script registered." -ForegroundColor Green
    #>
}
else {
    Write-Host "Auto-login will NOT be configured." -ForegroundColor Green
}

# ================================
# SECTION 4: Install and Promote to Domain Controller
# ================================

Write-Host ""
Write-Host "Installing Active Directory Domain Services and DNS..." -ForegroundColor Cyan

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
Install-WindowsFeature -Name DNS                  -IncludeManagementTools | Out-Null

Write-Host "Importing ADDSDeployment module..." -ForegroundColor Cyan
Import-Module ADDSDeployment

Write-Host ""
Write-Host "Promoting this server to Domain Controller for domain '$FQDN'..." -ForegroundColor Cyan
Write-Host "This will automatically reboot the server when finished." -ForegroundColor Yellow
Write-Host ""

# Final confirmation before no-return operation
$Proceed = Read-YesNo -Message "Ready to promote this server to a NEW forest with domain '$FQDN'?" -Default 'Y'
if (-not $Proceed) {
    Write-Host "Aborting before domain promotion. No changes made to AD DS." -ForegroundColor Yellow
    exit 1
}

Install-ADDSForest `
    -DomainName $FQDN `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword $SafeModeSecurePassword `
    -InstallDNS `
    -Force

Write-Host "Domain Controller promotion initiated. The system will now reboot automatically." -ForegroundColor Yellow
