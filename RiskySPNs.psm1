# Import this module to use all RiskySPNs tools
﻿# Import-Module .\RiskySPNs.psm1
Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking}
