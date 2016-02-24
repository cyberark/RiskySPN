# Import this module to use all RiskySPNs tools
﻿# Import-Module .\RiskySPNs.psm1
Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | % { . $_.FullName}
