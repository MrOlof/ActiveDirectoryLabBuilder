<#
    AutoDC-Deployment.ps1

    DESCRIPTION:
    Run this script AFTER the server has been promoted to a Domain Controller
    and you are logged in with a domain admin account.

    It will:
      * Ask for your domain FQDN (e.g. lab.local)
      * Ask for a root "lab" OU name
      * Create a sub-OU structure:
            <RootOU>
              ├─ External Users
              ├─ Service Accounts
              ├─ Standard Users
              ├─ Disabled Users
              └─ Elevated Users
      * Create some sample users and groups
      * Prompt for a new domain admin account name and password and add it to Domain Admins

    AUTHOR: MrOlof
#>

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        AD Lab Post-Deployment Script      " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ===========================
# Helper Functions
# ===========================

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

# ===========================
# Domain & OU Setup
# ===========================

# Ask for domain FQDN (e.g. lab.local)
$Fqdn = Get-NonEmptyInput -Message "Enter your AD domain FQDN (for example: lab.local)"

# Build domain DN (e.g. DC=lab,DC=local)
$domainParts = $Fqdn.Split('.') | Where-Object { $_ -ne '' }
if ($domainParts.Count -lt 2) {
    Write-Host "FQDN '$Fqdn' doesn't look valid (need at least domain.tld)." -ForegroundColor Red
    exit 1
}
$DomainDN = ($domainParts | ForEach-Object { "DC=$_" }) -join ','

# Sanity check – will throw if domain not reachable
try {
    $adDomain = Get-ADDomain -Identity $Fqdn -ErrorAction Stop
}
catch {
    Write-Host "Unable to query domain '$Fqdn'. Are you running on the DC and logged in as a domain admin?" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Root OU for this lab structure
$defaultRootOUName = $domainParts[0].ToUpper()
$RootOUName = Get-NonEmptyInput -Message "Enter name of the main lab OU (root OU)" -Default $defaultRootOUName

$RootOUDN          = "OU=$RootOUName,$DomainDN"
$ExternalOUDN      = "OU=External Users,$RootOUDN"
$ServiceAccountsOUDN = "OU=Service Accounts,$RootOUDN"
$StandardUsersOUDN = "OU=Standard Users,$RootOUDN"
$DisabledUsersOUDN = "OU=Disabled Users,$RootOUDN"
$ElevatedUsersOUDN = "OU=Elevated Users,$RootOUDN"

Write-Host ""
Write-Host "Creating OU structure under $DomainDN ..." -ForegroundColor Cyan

# Create root OU
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$RootOUName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $RootOUName -Path $DomainDN -ProtectedFromAccidentalDeletion $false
}

# Create sub OUs
foreach ($ou in @(
    @{ Name = "External Users"; DN = $ExternalOUDN },
    @{ Name = "Service Accounts"; DN = $ServiceAccountsOUDN },
    @{ Name = "Standard Users"; DN = $StandardUsersOUDN },
    @{ Name = "Disabled Users"; DN = $DisabledUsersOUDN },
    @{ Name = "Elevated Users"; DN = $ElevatedUsersOUDN }
)) {
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$($ou.Name))" -SearchBase $RootOUDN -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou.Name -Path $RootOUDN -ProtectedFromAccidentalDeletion $false
        Write-Host "Created OU: $($ou.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "OU already exists: $($ou.Name)" -ForegroundColor Yellow
    }
}

# ===========================
# Sample Groups
# ===========================

Write-Host ""
Write-Host "Creating lab security groups..." -ForegroundColor Cyan

# Groups located in the root lab OU
$Groups = @(
    @{ Name = "Standard Users Group"; Path = $StandardUsersOUDN },
    @{ Name = "External Users Group"; Path = $ExternalOUDN },
    @{ Name = "Elevated Users Group"; Path = $ElevatedUsersOUDN },
    @{ Name = "Service Accounts Group"; Path = $ServiceAccountsOUDN }
)

foreach ($g in $Groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($g.Name)'" -SearchBase $g.Path -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $g.Path | Out-Null
        Write-Host "Created group: $($g.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "Group already exists: $($g.Name)" -ForegroundColor Yellow
    }
}

# ===========================
# Default password for lab users
# ===========================

Write-Host ""
Write-Host "A password is needed for the sample lab users (not the domain admin)." -ForegroundColor Cyan
$DefaultUserPassword = Get-NonEmptyInput -Message "Enter default password for lab users (for example: Passw0rd!)" -Default "Passw0rd!"
$DefaultUserPasswordSecure = ConvertTo-SecureString $DefaultUserPassword -AsPlainText -Force

# ===========================
# Create Sample Users
# ===========================

Write-Host ""
Write-Host "Creating sample lab users..." -ForegroundColor Cyan

# Standard Users (American/European names)
$StandardUsers = @(
    @{ Name = "John Doe";        Sam = "john.doe" },
    @{ Name = "Anna Smith";      Sam = "anna.smith" },
    @{ Name = "Lars Eriksson";   Sam = "lars.eriksson" },
    @{ Name = "Emily Brown";     Sam = "emily.brown" }
)

foreach ($u in $StandardUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $StandardUsersOUDN -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $StandardUsersOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created user: $($u.Sam)" -ForegroundColor Green
    }
    else {
        Write-Host "User already exists: $($u.Sam)" -ForegroundColor Yellow
    }
}

# External Users
$ExternalUsers = @(
    @{ Name = "Mia Jensen";     Sam = "mia.jensen" },
    @{ Name = "Oliver Martin";  Sam = "oliver.martin" }
)

foreach ($u in $ExternalUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $ExternalOUDN -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $ExternalOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created external user: $($u.Sam)" -ForegroundColor Green
    }
    else {
        Write-Host "External user already exists: $($u.Sam)" -ForegroundColor Yellow
    }
}

# Service Accounts (generic lab service accounts)
$ServiceAccounts = @(
    @{ Name = "SQL Service Account";   Sam = "svc-sql" },
    @{ Name = "Web Service Account";   Sam = "svc-web" }
)

foreach ($u in $ServiceAccounts) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $ServiceAccountsOUDN -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $ServiceAccountsOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created service account: $($u.Sam)" -ForegroundColor Green
    }
    else {
        Write-Host "Service account already exists: $($u.Sam)" -ForegroundColor Yellow
    }
}

# ===========================
# Add Users to Groups
# ===========================

Write-Host ""
Write-Host "Adding users to lab groups..." -ForegroundColor Cyan

$standardGroup = Get-ADGroup -Filter "Name -eq 'Standard Users Group'" -SearchBase $StandardUsersOUDN -ErrorAction SilentlyContinue
if ($standardGroup) {
    $standardMembers = $StandardUsers | ForEach-Object { $_.Sam }
    Add-ADGroupMember -Identity $standardGroup -Members $standardMembers -ErrorAction SilentlyContinue
}

$externalGroup = Get-ADGroup -Filter "Name -eq 'External Users Group'" -SearchBase $ExternalOUDN -ErrorAction SilentlyContinue
if ($externalGroup) {
    $externalMembers = $ExternalUsers | ForEach-Object { $_.Sam }
    Add-ADGroupMember -Identity $externalGroup -Members $externalMembers -ErrorAction SilentlyContinue
}

$svcGroup = Get-ADGroup -Filter "Name -eq 'Service Accounts Group'" -SearchBase $ServiceAccountsOUDN -ErrorAction SilentlyContinue
if ($svcGroup) {
    $svcMembers = $ServiceAccounts | ForEach-Object { $_.Sam }
    Add-ADGroupMember -Identity $svcGroup -Members $svcMembers -ErrorAction SilentlyContinue
}

# ===========================
# Create Domain Admin (Prompted)
# ===========================

Write-Host ""
Write-Host "Create a new domain admin account." -ForegroundColor Cyan

$DomainAdminSam  = Get-NonEmptyInput -Message "Enter the SamAccountName for the new domain admin (for example: labadmin)"
$DomainAdminName = Get-NonEmptyInput -Message "Enter the display name for the new domain admin (for example: Lab Admin)"

$DomainAdminPasswordSecure = Read-Host "Enter the password for $DomainAdminSam" -AsSecureString

# Create domain admin user in Elevated Users OU
if (-not (Get-ADUser -Filter "SamAccountName -eq '$DomainAdminSam'" -SearchBase $ElevatedUsersOUDN -ErrorAction SilentlyContinue)) {
    New-ADUser `
        -Name $DomainAdminName `
        -SamAccountName $DomainAdminSam `
        -UserPrincipalName ("{0}@{1}" -f $DomainAdminSam, $Fqdn) `
        -AccountPassword $DomainAdminPasswordSecure `
        -Enabled $true `
        -Path $ElevatedUsersOUDN `
        -GivenName ($DomainAdminName.Split(' ')[0]) `
        -Surname ($DomainAdminName.Split(' ')[-1]) `
        -ChangePasswordAtLogon $false | Out-Null

    Write-Host "Created domain admin user: $DomainAdminSam" -ForegroundColor Green
}
else {
    Write-Host "User with SamAccountName '$DomainAdminSam' already exists in Elevated Users OU." -ForegroundColor Yellow
}

# Add to Domain Admins + Elevated Users Group
$domainAdminsGroup = Get-ADGroup -Identity "Domain Admins" -ErrorAction SilentlyContinue
if ($domainAdminsGroup) {
    Add-ADGroupMember -Identity $domainAdminsGroup -Members $DomainAdminSam -ErrorAction SilentlyContinue
    Write-Host "Added $DomainAdminSam to Domain Admins." -ForegroundColor Green
}
else {
    Write-Host "Could not find 'Domain Admins' group. Skipping Domain Admins membership." -ForegroundColor Red
}

$elevatedGroup = Get-ADGroup -Filter "Name -eq 'Elevated Users Group'" -SearchBase $ElevatedUsersOUDN -ErrorAction SilentlyContinue
if ($elevatedGroup) {
    Add-ADGroupMember -Identity $elevatedGroup -Members $DomainAdminSam -ErrorAction SilentlyContinue
    Write-Host "Added $DomainAdminSam to Elevated Users Group." -ForegroundColor Green
}

Write-Host ""
Write-Host "Lab deployment completed. OU structure, groups, sample users, and domain admin have been configured." -ForegroundColor Cyan
