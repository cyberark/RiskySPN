# PowerShell Module file
Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer } | % { Import-Module $_.FullName -DisableNameChecking}