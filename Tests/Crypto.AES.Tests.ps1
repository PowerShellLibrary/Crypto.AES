Clear-Host
Import-Module -Name Pester -Force
Import-Module .\Crypto.AES\Crypto.AES.psm1 -Force

Describe 'Crypto.AES.Tests' {
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

    Context "IVGenerator" {
        $obj = [IVGenerator]::new()
        $v1 = $obj.GenerateIV()
        $v2 = $obj.GenerateIV()

        It "Should return valid type" {
            $v1 -is [System.Byte[]] | Should -BeTrue
        }
        It "Should generate unique keys" {
            $v1 | Should -Not -Be $v2
        }
    }
}