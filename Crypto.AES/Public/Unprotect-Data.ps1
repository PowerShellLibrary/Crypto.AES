function Unprotect-Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Key" )]
        [byte[]]$Key,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "GCM" )]
        [System.Security.Cryptography.AesGcm]$GCM,
        [Parameter(Mandatory = $true, Position = 1 )]
        [byte[]]$Data,
        [Parameter(Mandatory = $true, Position = 2 )]
        [byte[]]$Nonce,
        [Parameter(Mandatory = $true, Position = 3 )]
        [byte[]]$Tag
    )

    begin {
        Write-Verbose "Cmdlet Unprotect-Data - Begin"
    }

    process {
        Write-Verbose "Cmdlet Unprotect-Data - Process"
        $decrypted = [byte[]]::new($Data.Length)

        if ($PSCmdlet.ParameterSetName -eq 'Key') {
            $gcm = [System.Security.Cryptography.AesGcm]::new($Key)
        }
        $gcm.Decrypt($nonce, $Data, $Tag, $decrypted)
        Write-Output $decrypted -NoEnumerate
    }

    end {
        Write-Verbose "Cmdlet Unprotect-Data - End"
    }
}