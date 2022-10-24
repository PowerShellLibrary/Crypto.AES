enum AesKeyFormat {
    String
    ByteArray
}

function New-AesKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0 )]
        [AesKeyFormat]$Format = [AesKeyFormat]::String
    )

    begin {
        Write-Verbose "Cmdlet New-AesKey - Begin"
    }

    process {
        Write-Verbose "Cmdlet New-AesKey - Process"
        $aes = New-AesManagedObject
        $aes.GenerateKey()

        if ($Format -eq [AesKeyFormat]::String) {
            [System.Convert]::ToBase64String($aes.Key)
        }
        elseif ($Format -eq [AesKeyFormat]::ByteArray) {
            $aes.Key
        }
    }

    end {
        Write-Verbose "Cmdlet New-AesKey - End"
    }
}