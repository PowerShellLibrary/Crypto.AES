function New-AesManagedObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0 )]
        $Key,
        [Parameter(Mandatory = $false, Position = 1 )]
        $InitializationVector,
        [Parameter(Mandatory = $false, Position = 2 )]
        [System.Security.Cryptography.CipherMode]$Mode = [System.Security.Cryptography.CipherMode]::CBC,
        [Parameter(Mandatory = $false, Position = 3 )]
        [System.Security.Cryptography.PaddingMode]$Padding = [System.Security.Cryptography.PaddingMode]::Zeros,
        [Parameter(Mandatory = $false, Position = 4 )]
        [int]$BlockSize = 128,
        [Parameter(Mandatory = $false, Position = 5 )]
        [int]$KeySize = 256
    )

    begin {
        Write-Verbose "Cmdlet New-AesManagedObject - Begin"
    }

    process {
        Write-Verbose "Cmdlet New-AesManagedObject - Process"
        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $aesManaged.Mode = $Mode
        $aesManaged.Padding = $Padding
        $aesManaged.BlockSize = $BlockSize
        $aesManaged.KeySize = $KeySize
        if ($InitializationVector) {
            if ($InitializationVector.getType().Name -eq "String") {
                $aesManaged.IV = [System.Convert]::FromBase64String($InitializationVector)
            }
            else {
                $aesManaged.IV = $InitializationVector
            }
        }
        if ($Key) {
            if ($Key.getType().Name -eq "String") {
                $aesManaged.Key = [System.Convert]::FromBase64String($Key)
            }
            else {
                $aesManaged.Key = $Key
            }
        }
        $aesManaged
    }

    end {
        Write-Verbose "Cmdlet New-AesManagedObject - End"
    }
}