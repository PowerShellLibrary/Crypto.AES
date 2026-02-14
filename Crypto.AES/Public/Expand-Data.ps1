function Expand-Data {
    param (
        [Parameter(Mandatory = $true, Position = 0 )]
        [byte[]]$Payload
    )
    $size = $Payload.Length - 12 - 1
    @{
        tag   = $Payload[0..15]
        data  = $Payload[16..$size]
        nonce = $Payload[($size + 1)..$Payload.Length]
    }
}