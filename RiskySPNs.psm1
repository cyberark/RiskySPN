<# 
    Author: Matan Hart
    Contact: cyberark.labs@cyberark.com
    License: GNU v3
    Requirements: PowerShell v3+

Import this module to use all RiskySPNs tools
Import-Module .\RiskySPNs.psm1
#>
Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | % {Import-Module $_.FullName -WarningAction SilentlyContinue}
