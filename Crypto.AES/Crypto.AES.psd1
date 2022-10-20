
@{
    RootModule        = 'Crypto.AES.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '11dfc05f-b1e6-4ff9-87fc-7ff4dca7457e'
    Author            = 'Alan Plocieniak'
    CompanyName       = 'Alan Plocieniak'
    Copyright         = '(c) 2022 Alan Plocieniak. All rights reserved.'
    Description       = 'PowerShell module for cryptography (AES)'
    PowerShellVersion = '5.0'
    FunctionsToExport = '*'
    ScriptsToProcess  = @('Public\Classes\IVGenerator.ps1')
    PrivateData       = @{
        PSData = @{
        }
    }
}