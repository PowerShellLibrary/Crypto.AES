function Get-RandomNonce {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length
    )

    begin {
        Write-Verbose "Cmdlet Get-RandomNonce - Begin"
    }

    process {
        Write-Verbose "Cmdlet Get-RandomNonce - Generating a nonce of length $Length"

        $nonce = [byte[]]::new($Length)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        Write-Output $nonce -NoEnumerate
    }

    end {
        Write-Verbose "Cmdlet Get-RandomNonce - End"
    }
}