class IVGenerator {
    [System.Security.Cryptography.AesManaged]$AesManaged
    IVGenerator() {
        $this.AesManaged = New-AesManagedObject
    }

    [byte[]] GenerateIV () {
        $this.AesManaged.GenerateIV()
        return $this.AesManaged.IV
    }
}