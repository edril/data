param(
    [Parameter(Mandatory = $true)][string]$UPN,
    [switch]$NoForensics,
    [switch]$NoPasswordReset,
    [switch]$NoMFA,
    [switch]$NoDisableForwardingRules,
    [switch]$NoRevokeRefreshTokens,
    [switch]$NoDisableCalendarPublishing,
    [switch]$NoRemoveDelegates,
    [switch]$NoRemoveMailboxForwarding,
    [switch]$NoDisableMobileDevices,
    [switch]$ConfirmAll,
    [ValidateSet("Commercial", "USGovGCC", "USGovGCCHigh", "USGovDoD", "China")]
    [string]$CloudEnvironment = "Commercial"
)

$Result = @{
    UPN = $UPN
    Actions = @()
    Notes = @()
    Errors = @()
}

# Auth: Use Managed Identity
try {
    Connect-AzAccount -Identity | Out-Null
    Connect-ExchangeOnline -ManagedIdentity -ShowBanner:$false
    Connect-MgGraph -Scopes @(
        "UserAuthenticationMethod.ReadWrite.All",
        "Policy.ReadWrite.AuthenticationMethod",
        "User.RevokeSessions.All"
    ) -Environment $CloudEnvironment -NoWelcome -ContextScope Process | Out-Null
    Connect-AzureAD -ManagedServiceIdentity
    Connect-MsolService -ManagedServiceIdentity
    $Result.Actions += "Authenticated with Managed Identity"
} catch {
    $Result.Errors += "Authentication failed: $($_.Exception.Message)"
    $Result.success = $false
    $Result | ConvertTo-Json -Depth 10
    return
}

# Get mailbox
try {
    $Mailbox = Get-Mailbox -Identity $UPN -ErrorAction Stop
    $Result.Actions += "Mailbox found: $($Mailbox.DisplayName)"
} catch {
    $Result.Errors += "Could not locate mailbox for $UPN"
    $Result.success = $false
    $Result | ConvertTo-Json -Depth 10
    return
}

# Remediation actions
if (-not $NoPasswordReset) {
    try {
        $NewPassword = [System.Web.Security.Membership]::GeneratePassword(14,3)
        Set-MsolUserPassword -UserPrincipalName $UPN -NewPassword $NewPassword -ForceChangePassword $true
        $Result.Actions += "Password reset"
        $Result.NewPassword = $NewPassword
    } catch {
        $Result.Errors += "Password reset failed: $($_.Exception.Message)"
    }
}

if (-not $NoMFA) {
    try {
        $uri = "/beta/users/$UPN/authentication/requirements"
        $body = @{ perUserMfaState = 'enforced' } | ConvertTo-Json
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json'
        $Result.Actions += "MFA enforced"
    } catch {
        $Result.Errors += "MFA setup failed: $($_.Exception.Message)"
    }
}

if (-not $NoRevokeRefreshTokens) {
    try {
        Invoke-MgGraphRequest -Method POST -Uri "/v1.0/users/$UPN/revokeSignInSessions"
        $Result.Actions += "Refresh tokens revoked"
    } catch {
        $Result.Errors += "Revoke failed: $($_.Exception.Message)"
    }
}

if (-not $NoDisableForwardingRules) {
    try {
        $rules = Get-InboxRule -Mailbox $UPN | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo }
        if ($rules) {
            $rules | Remove-InboxRule -Confirm:$false
            $Result.Actions += "Inbox rules removed"
        } else {
            $Result.Notes += "No inbox rules found"
        }
    } catch {
        $Result.Errors += "Inbox rule removal failed: $($_.Exception.Message)"
    }
}

if (-not $NoDisableCalendarPublishing) {
    try {
        $calFolder = "$($Mailbox.Identity):\Calendar"
        Set-MailboxCalendarFolder -Identity $calFolder -PublishEnabled:$false
        $Result.Actions += "Calendar publishing disabled"
    } catch {
        $Result.Errors += "Calendar publishing removal failed: $($_.Exception.Message)"
    }
}

if (-not $NoRemoveDelegates) {
    try {
        $delegates = Get-MailboxPermission -Identity $UPN | Where-Object { !$_.IsInherited -and $_.User -notlike "*SELF*" }
        foreach ($d in $delegates) {
            Remove-MailboxPermission -Identity $UPN -User $d.User -AccessRights $d.AccessRights -InheritanceType All -Confirm:$false
        }
        $Result.Actions += "Delegates removed"
    } catch {
        $Result.Errors += "Delegate removal failed: $($_.Exception.Message)"
    }
}

if (-not $NoRemoveMailboxForwarding) {
    try {
        Set-Mailbox -Identity $UPN -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null
        $Result.Actions += "Mailbox forwarding removed"
    } catch {
        $Result.Errors += "Forwarding removal failed: $($_.Exception.Message)"
    }
}

if (-not $NoDisableMobileDevices) {
    try {
        $devices = Get-MobileDevice -Mailbox $UPN
        if ($devices) {
            $ids = $devices.DeviceId
            Set-CASMailbox $UPN -ActiveSyncBlockedDeviceIDs $ids
            $Result.Actions += "Mobile devices blocked"
        } else {
            $Result.Notes += "No devices found"
        }
    } catch {
        $Result.Errors += "Device block failed: $($_.Exception.Message)"
    }
}

if (-not $NoForensics) {
    try {
        $forensics = @{
            Rules = Get-InboxRule -Mailbox $UPN
            Delegates = Get-MailboxPermission -Identity $UPN | Where-Object { !$_.IsInherited -and $_.User -notlike "*SELF*" }
            Devices = Get-MobileDevice -Mailbox $UPN
        }
        $Result.Forensics = $forensics
        $Result.Actions += "Forensics data collected"
    } catch {
        $Result.Errors += "Forensics export failed: $($_.Exception.Message)"
    }
}

$Result.success = $Result.Errors.Count -eq 0
$Result | ConvertTo-Json -Depth 10
