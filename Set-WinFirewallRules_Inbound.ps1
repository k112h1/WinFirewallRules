<#
.SYNOPSIS
    Automates the creation and update of Windows Firewall inbound rules from a CSV file.

.DESCRIPTION
    This script reads a CSV file containing firewall rule definitions and applies them using New-NetFirewallRule and Set-NetFirewallRule.
    - For each unique combination of DisplayName, Protocol, RemoteAddress, and Profile in the CSV, a single inbound firewall rule is created or updated.
    - All LocalPort values for the same DisplayName, Protocol, RemoteAddress, and Profile are combined and set as allowed ports in one rule.
    - If there are multiple patterns for RemoteAddress or Profile with the same DisplayName, the script creates separate rules by appending Protocol, RemoteAddress, and Profile to the DisplayName.
    - TestMode allows previewing the commands without applying them.
    After processing, the script outputs the current inbound firewall rules including LocalPort and RemoteAddress.

.PARAMETER CsvPath
    Path to the CSV file containing firewall rule definitions.

.PARAMETER TestMode
    If specified, commands will be printed and logged but not executed.

.PARAMETER Help
    Displays help information.

.EXAMPLE
    .\Set-WinFirewallRules.ps1 -CsvPath ".\rules.csv"
    .\Set-WinFirewallRules.ps1 -CsvPath ".\rules.csv" -TestMode
    .\Set-WinFirewallRules.ps1 -Help
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [switch]$TestMode,

    [switch]$Help
)

if ($Help -or -not $CsvPath) {
    Get-Help -Detailed $MyInvocation.MyCommand.Path
    exit 0
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logDir = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory | Out-Null
}
$logFile = Join-Path $logDir "${timestamp}_SetWinFirewall_result.log"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $line = "[$Level] $Message"
    Write-Host $line
    $line | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Administrator privileges are required to run this script." "ERROR"
    exit 1
}

# Validate CSV file
if (-not (Test-Path $CsvPath)) {
    Write-Log "CSV file '$CsvPath' not found." "ERROR"
    exit 1
}

try {
    $rules = Import-Csv -Path $CsvPath
} catch {
    Write-Log "Error reading CSV file: $($_.Exception.Message)" "ERROR"
    exit 1
}

$totalCount = $rules.Count
$successCount = 0

Write-Log "Loaded $totalCount rule(s) from CSV."

# Group rules by DisplayName, Protocol, RemoteAddress, Profile
# 一つのグループの中に複数のLocalPortを含む:
# Group 1: 
#   DisplayName1, Protocol1, RemoteAddress1, Profile1
#   Group: LocalPort1, LocalPort2, LocalPort3
# Group 2: 
#   DisplayName2, Protocol2, RemoteAddress2, Profile2
#   Group: LocalPort1, LocalPort2, LocalPort3

$grouped = $rules | Group-Object Name, Protocol, RemoteAddress, Profile

foreach ($group in $grouped) {
    $name = $group.Group[0].Name
    $protocol = $group.Group[0].Protocol
    $remoteAddress = $group.Group[0].RemoteAddress
    $profile = $group.Group[0].Profile
    $direction = "Inbound"
    $action = "Allow"
    $localPorts = ($group.Group | ForEach-Object { $_.LocalPort }) -join ","

    # もし同じDisplayNameでremoteAddressやprofileが異なる場合はDisplayNameにsuffixを付与
    $displayName = $name
    $groupCount = ($grouped | Where-Object { $_.Group[0].Name -eq $name }).Count
    if ($groupCount -gt 1) {
        $displayName = "${name}_${protocol}_${remoteAddress}_${profile}"
    }

    $existingRule = Get-NetFirewallRule -DisplayName $displayName -Direction $direction -ErrorAction SilentlyContinue

    if (-not $existingRule) {
        $cmd = "New-NetFirewallRule -DisplayName `"$displayName`" -Direction $direction -Action $action -Protocol $protocol -LocalPort $localPorts -RemoteAddress $remoteAddress -Profile $profile"
        if ($TestMode) {
            Write-Log "[TestMode] $cmd"
        } else {
            try {
                Invoke-Expression $cmd
                Write-Log "Created rule: $displayName"
            } catch {
                Write-Log "Failed to create rule: $displayName - $($_.Exception.Message)" "ERROR"
                continue
            }
        }
        $existingRule = Get-NetFirewallRule -DisplayName $displayName -Direction $direction -ErrorAction SilentlyContinue
    }

    if ($existingRule) {
        if ($TestMode) {
            Write-Log "[TestMode] Set-NetFirewallRule -DisplayName `"$displayName`" -Direction $direction -Action $action -Profile $profile"
            Write-Log "[TestMode] Set-NetFirewallPortFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -DisplayName `"$displayName`") -Protocol $protocol -LocalPort $localPorts"
            Write-Log "[TestMode] Set-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -DisplayName `"$displayName`") -RemoteAddress $remoteAddress"
        } else {
            try {
                Set-NetFirewallRule -DisplayName $displayName -Direction $direction -Action $action -Profile $profile
                Set-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule -Protocol $protocol -LocalPort $localPorts
                Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $existingRule -RemoteAddress $remoteAddress
                Write-Log "Updated rule: $displayName"
                $successCount++
            } catch {
                Write-Log "Failed to update rule: $displayName - $($_.Exception.Message)" "ERROR"
            }
        }
    }
}

Write-Log "Processed $totalCount rule(s). Successfully applied $successCount rule(s)."

# Output current inbound rules
Write-Log "Current inbound firewall rules:"
$inboundRules = Get-NetFirewallRule -Direction Inbound | Sort-Object DisplayName
foreach ($rule in $inboundRules) {
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
    $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
    $line = "{0,-30} {1,-7} {2,-6} {3,-8} {4,-8} {5,-10} {6}" -f $rule.DisplayName, $rule.Enabled, $rule.Action, $rule.Profile, $rule.Direction, $portFilter.LocalPort, $addrFilter.RemoteAddress
    Write-Log $line
}
