function Protect-Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Key")]
        [byte[]]$Key,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "GCM")]
        [System.Security.Cryptography.AesGcm]$GCM,

        [Parameter(Mandatory = $true, Position = 1)]
        [byte[]]$Data,

        [Parameter(Mandatory = $false, Position = 2)]
        [byte[]]$Nonce,

        [Parameter(Mandatory = $false, Position = 3)]
        [Switch]$Combined
    )

    begin {
        Write-Verbose "Cmdlet Protect-Data - Begin"
    }

    process {
        Write-Verbose "Cmdlet Protect-Data - Process"
        if (!$Nonce) {
            $Nonce = Get-RandomNonce -Length 12
        }
        $cipherOutput = [byte[]]::new($Data.Length)
        $tag = [byte[]]::new(16)

        if ($PSCmdlet.ParameterSetName -eq 'Key') {
            if ($Key.Length -notin @(16, 24, 32)) {
                throw "Invalid AES key length. Must be 16, 24, or 32 bytes."
            }
            $GCM = [System.Security.Cryptography.AesGcm]::new($Key)
            try {
                $GCM.Encrypt($Nonce, $Data, $cipherOutput, $tag)
            }
            finally {
                $GCM.Dispose()
            }
        }
        else {
            $GCM.Encrypt($Nonce, $Data, $cipherOutput, $tag)
        }

        if ($Combined) {
            $output = [byte[]]::new($cipherOutput.Length + $Nonce.Length + $tag.Length)
            [System.Buffer]::BlockCopy($tag, 0, $output, 0, $tag.Length)
            [System.Buffer]::BlockCopy($cipherOutput, 0, $output, $tag.Length, $cipherOutput.Length)
            [System.Buffer]::BlockCopy($Nonce, 0, $output, $tag.Length + $cipherOutput.Length, $Nonce.Length)
            Write-Output $output -NoEnumerate
        }
        else {
            @{
                CipherText = $cipherOutput
                Nonce      = $Nonce
                Tag        = $tag
            }
        }
    }

    end {
        Write-Verbose "Cmdlet Protect-Data - End"
    }
}