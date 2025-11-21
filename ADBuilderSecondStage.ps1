<#
    AutoDC-Deployment.ps1

    DESCRIPTION:
    Run this script AFTER the server has been promoted to a Domain Controller
    and you are logged in with a domain admin account.

    It will:
      * Auto-detect your domain FQDN and DN from AD
      * Ask for a root "lab" OU name
      * Create a sub-OU structure:
            <RootOU>
              ├─ External Users
              ├─ Service Accounts
              ├─ Standard Users
              ├─ Disabled Users
              └─ Elevated Users
      * Create some sample users and groups
      * Give users random departments / roles (Title) and descriptions
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

Write-Host "Detecting current Active Directory domain..." -ForegroundColor Cyan

try {
    # Get current domain info from AD – no need to type the FQDN
    $adDomain = Get-ADDomain -ErrorAction Stop
}
catch {
    Write-Host "Unable to query the current AD domain. Are you running on a DC and logged in as a domain admin?" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$Fqdn        = $adDomain.DNSRoot           # e.g. lab.local
$DomainDN    = $adDomain.DistinguishedName # e.g. DC=lab,DC=local
$NetbiosName = $adDomain.NetBIOSName       # e.g. LAB

Write-Host ""
Write-Host "Detected domain:" -ForegroundColor Cyan
Write-Host "  FQDN:        $Fqdn"
Write-Host "  DN:          $DomainDN"
Write-Host "  NetBIOS:     $NetbiosName"
Write-Host ""

# Root OU for this lab structure
$defaultRootOUName = $NetbiosName
$RootOUName = Get-NonEmptyInput -Message "Enter name of the main lab OU (root OU)" -Default $defaultRootOUName

$RootOUDN            = "OU=$RootOUName,$DomainDN"
$ExternalOUDN        = "OU=External Users,$RootOUDN"
$ServiceAccountsOUDN = "OU=Service Accounts,$RootOUDN"
$StandardUsersOUDN   = "OU=Standard Users,$RootOUDN"
$DisabledUsersOUDN   = "OU=Disabled Users,$RootOUDN"
$ElevatedUsersOUDN   = "OU=Elevated Users,$RootOUDN"

Write-Host "Creating OU structure under $DomainDN ..." -ForegroundColor Cyan

# Create root OU
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$RootOUName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $RootOUName -Path $DomainDN -ProtectedFromAccidentalDeletion $false
    Write-Host "Created root OU: $RootOUName" -ForegroundColor Green
}
else {
    Write-Host "Root OU already exists: $RootOUName" -ForegroundColor Yellow
}

# Create sub OUs
foreach ($ou in @(
    @{ Name = "External Users";      DN = $ExternalOUDN },
    @{ Name = "Service Accounts";    DN = $ServiceAccountsOUDN },
    @{ Name = "Standard Users";      DN = $StandardUsersOUDN },
    @{ Name = "Disabled Users";      DN = $DisabledUsersOUDN },
    @{ Name = "Elevated Users";      DN = $ElevatedUsersOUDN }
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

$Groups = @(
    @{ Name = "Standard Users Group";   Path = $StandardUsersOUDN },
    @{ Name = "External Users Group";   Path = $ExternalOUDN },
    @{ Name = "Elevated Users Group";   Path = $ElevatedUsersOUDN },
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
# Department / Title pools
# ===========================

$Departments = @(
    "IT",
    "HR",
    "Finance",
    "Sales",
    "Marketing",
    "Operations",
    "Support"
)

$UserTitles = @(
    "Helpdesk Technician",
    "Systems Administrator",
    "Network Engineer",
    "IT Support Specialist",
    "HR Specialist",
    "Recruiter",
    "Accountant",
    "Financial Analyst",
    "Sales Representative",
    "Account Manager",
    "Marketing Coordinator",
    "Digital Marketing Specialist",
    "Operations Coordinator",
    "Operations Manager",
    "Customer Support Agent"
)

$ServiceTitles = @(
    "Application Service Account",
    "Database Service Account",
    "Web Service Account",
    "Automation Service Account",
    "Monitoring Service Account"
)

# Helper to generate department/title/description
function New-LabUserMetadata {
    param(
        [string]$Type = "User"  # "User" or "Service"
    )

    if ($Type -eq "Service") {
        $dept  = "IT"
        $title = $ServiceTitles | Get-Random
        $desc  = "Service account - $title"
    }
    else {
        $dept  = $Departments | Get-Random
        $title = $UserTitles  | Get-Random
        $desc  = "Lab user - $dept - $title"
    }

    [PSCustomObject]@{
        Department  = $dept
        Title       = $title
        Description = $desc
    }
}

# ===========================
# Create Sample Users
# ===========================

Write-Host ""
Write-Host "Creating sample lab users..." -ForegroundColor Cyan

# Standard Users (American/European names)
$StandardUsers = @(
    @{ Name = "John Doe";       Sam = "john.doe" },
    @{ Name = "Anna Smith";     Sam = "anna.smith" },
    @{ Name = "Lars Eriksson";  Sam = "lars.eriksson" },
    @{ Name = "Emily Brown";    Sam = "emily.brown" }
)

foreach ($u in $StandardUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $StandardUsersOUDN -ErrorAction SilentlyContinue)) {

        $meta = New-LabUserMetadata -Type "User"

        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $StandardUsersOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -Department $meta.Department `
            -Title $meta.Title `
            -Description $meta.Description `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created user: $($u.Sam)  [$($meta.Department) - $($meta.Title)]" -ForegroundColor Green
    }
    else {
        Write-Host "User already exists: $($u.Sam)" -ForegroundColor Yellow
    }
}

# External Users
$ExternalUsers = @(
    @{ Name = "Mia Jensen";    Sam = "mia.jensen" },
    @{ Name = "Oliver Martin"; Sam = "oliver.martin" }
)

foreach ($u in $ExternalUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $ExternalOUDN -ErrorAction SilentlyContinue)) {

        $meta = New-LabUserMetadata -Type "User"

        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $ExternalOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -Department $meta.Department `
            -Title $meta.Title `
            -Description $meta.Description `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created external user: $($u.Sam)  [$($meta.Department) - $($meta.Title)]" -ForegroundColor Green
    }
    else {
        Write-Host "External user already exists: $($u.Sam)" -ForegroundColor Yellow
    }
}

# Service Accounts
$ServiceAccounts = @(
    @{ Name = "SQL Service Account"; Sam = "svc-sql" },
    @{ Name = "Web Service Account"; Sam = "svc-web" }
)

foreach ($u in $ServiceAccounts) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -SearchBase $ServiceAccountsOUDN -ErrorAction SilentlyContinue)) {

        $meta = New-LabUserMetadata -Type "Service"

        New-ADUser `
            -Name $u.Name `
            -SamAccountName $u.Sam `
            -UserPrincipalName ("{0}@{1}" -f $u.Sam, $Fqdn) `
            -AccountPassword $DefaultUserPasswordSecure `
            -Enabled $true `
            -Path $ServiceAccountsOUDN `
            -GivenName ($u.Name.Split(' ')[0]) `
            -Surname ($u.Name.Split(' ')[-1]) `
            -Department $meta.Department `
            -Title $meta.Title `
            -Description $meta.Description `
            -ChangePasswordAtLogon $false | Out-Null

        Write-Host "Created service account: $($u.Sam)  [$($meta.Title)]" -ForegroundColor Green
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

if (-not (Get-ADUser -Filter "SamAccountName -eq '$DomainAdminSam'" -SearchBase $ElevatedUsersOUDN -ErrorAction SilentlyContinue)) {

    # Give the domain admin a more "senior" role description
    $adminMeta = [PSCustomObject]@{
        Department  = "IT"
        Title       = "Domain Administrator"
        Description = "Lab domain admin account"
    }

    New-ADUser `
        -Name $DomainAdminName `
        -SamAccountName $DomainAdminSam `
        -UserPrincipalName ("{0}@{1}" -f $DomainAdminSam, $Fqdn) `
        -AccountPassword $DomainAdminPasswordSecure `
        -Enabled $true `
        -Path $ElevatedUsersOUDN `
        -GivenName ($DomainAdminName.Split(' ')[0]) `
        -Surname ($DomainAdminName.Split(' ')[-1]) `
        -Department $adminMeta.Department `
        -Title $adminMeta.Title `
        -Description $adminMeta.Description `
        -ChangePasswordAtLogon $false | Out-Null

    Write-Host "Created domain admin user: $DomainAdminSam  [$($adminMeta.Title)]" -ForegroundColor Green
}
else {
    Write-Host "User with SamAccountName '$DomainAdminSam' already exists in Elevated Users OU." -ForegroundColor Yellow
}

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
Write-Host "Lab deployment completed. OU structure, groups, sample users (with departments/roles), and domain admin have been configured." -ForegroundColor Cyan
