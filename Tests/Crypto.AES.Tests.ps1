Import-Module .\Crypto.AES\Crypto.AES.psm1 -Force

Describe 'Crypto.AES.Tests' {
    BeforeAll {
        $encoding = [System.Text.UTF8Encoding]::new()
    }

    Context "AES key generation" {
        It "Should return key as string - default" {
            New-AesKey | Should -BeOfType [String]
        }
        It "Should return key as string - explicit" {
            New-AesKey -Format String | Should -BeOfType [String]
        }
        It "Should return key as Object[]- explicit" {
            (New-AesKey -Format ByteArray) -is [System.Object[]] | Should -BeTrue
        }
    }

    Context "Protect-Data - parameter validation" {
        It "Throws error for invalid key length" {
            { Protect-Data -Key ([byte[]]::new(10)) -Data ([byte[]]::new(16)) } | Should -Throw "Invalid AES key length. Must be 16, 24, or 32 bytes."
        }
    }

    Context "Protect-Data - Result" {
        BeforeAll {
            $Key = [byte[]]::new(32)
            $nonce = [byte[]]::new(12)
            $data = $encoding.GetBytes("Test")
        }

        It "has correct size" {
            $r_key = Protect-Data -Key $Key -Data $data -Nonce $nonce

            $r_key.CipherText.Length | Should -BeExactly $data.Length
            $r_key.Nonce.Length | Should -BeExactly $nonce.Length
            $r_key.Tag.Length | Should -BeExactly 16
        }

        It "combined=false" {
            $r = Protect-Data -Key $Key -Data $data -Nonce $nonce

            $r.CipherText | Should -Not -BeNullOrEmpty
            $r.Nonce | Should -Not -BeNullOrEmpty
            $r.Tag | Should -Not -BeNullOrEmpty
            $r | Should -BeOfType [hashtable]

        }

        It "combined=true" {
            $r = Protect-Data -Key $Key -Data $data -Nonce $nonce -Combined

            $r.CipherText | Should -BeNullOrEmpty
            $r.Nonce | Should -BeNullOrEmpty
            $r.Tag | Should -BeNullOrEmpty
            $r -is [byte[]] | Should -BeTrue
            $r.Length | Should -BeExactly ($data.Length + $nonce.Length + 16)
        }
    }

    Context "Protect-Data - signature" {
        BeforeAll {
            $Key = [byte[]]::new(32)
            $nonce = [byte[]]::new(12)
            $nonce[0] = 104 # random value to test with mock
            $data = $encoding.GetBytes("Test")

            Mock -CommandName Get-RandomNonce -ModuleName Crypto.AES -MockWith {
                Write-Output $nonce -NoEnumerate
            }
        }

        It "optional nonce" {
            $r_explicit = Protect-Data -Key $Key -Data $data -Nonce $nonce
            $r_default = Protect-Data -Key $Key -Data $data -Nonce $null

            $r_explicit.CipherText | Should -BeExactly $r_default.CipherText
            $r_explicit.Nonce | Should -BeExactly $r_default.Nonce
            $r_explicit.Tag | Should -BeExactly $r_default.Tag
        }

        It "different parameter sets = same result" {
            $r_key = Protect-Data -Key $Key -Data $data -Nonce $nonce

            $gcm = [System.Security.Cryptography.AesGcm]::new($Key)
            $r_gcm = Protect-Data $gcm -Data $data -Nonce $nonce

            $r_key.CipherText | Should -BeExactly $r_gcm.CipherText
            $r_key.Nonce | Should -BeExactly $r_gcm.Nonce
            $r_key.Tag | Should -BeExactly $r_gcm.Tag
        }
    }

    Context "Protect-Data - nonce" {
        BeforeAll {
            $Key = [byte[]]::new(32)
            $nonce = [byte[]]::new(12)
            $data = $encoding.GetBytes("Test")
        }

        It "the same nonce" {
            $a = Protect-Data -Key $Key -Data $data -Nonce $nonce
            $b = Protect-Data -Key $Key -Data $data -Nonce $nonce

            $a.CipherText | Should -BeExactly $b.CipherText
            $a.Tag | Should -BeExactly $b.Tag
            $a.Nonce | Should -BeExactly $b.Nonce
        }
        It "different nonce" {
            $a = Protect-Data -Key $Key -Data $data -Nonce $nonce
            $different = $nonce[0..11]
            $different[11]++

            $b = Protect-Data -Key $Key -Data $data -Nonce $different

            $a.CipherText | Should -not -BeExactly $b.CipherText
            $a.Tag | Should -not -BeExactly $b.Tag
            $a.Nonce | Should -not -BeExactly $b.Nonce
        }
    }

    Context "Unprotect-Data" {
        BeforeAll {
            $Key = [byte[]]::new(32)
            [byte[]]$nonce = @(228, 132, 78, 5, 31, 60, 78, 70, 192, 119, 50, 184)
            [byte[]]$tag = @(188, 136, 244, 158, 253, 2, 183, 117, 127, 2, 193, 66, 39, 37, 94, 188)
            $data = @(48, 22, 117, 218 )
        }

        It "has correct size" {
            $r_key = Unprotect-Data -Key $Key -Data $data -Nonce $nonce -Tag $tag
            $r_key.Length | Should -BeExactly $data.Length
        }

        It "different parameter sets = same result" {
            $r_key = Unprotect-Data -Key $Key -Data $data -Nonce $nonce -Tag $tag

            $gcm = [System.Security.Cryptography.AesGcm]::new($Key)
            $r_gcm = Unprotect-Data $gcm -Data $data -Nonce $nonce -Tag $tag

            $r_key | Should -BeExactly $r_gcm
        }
    }
}