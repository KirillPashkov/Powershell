$obj = @()
[System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object Location |
        Select-Object FullName, Location |
            ForEach-Object {
                $f = $_.FullName -split ','
                $props = [ordered]@{
                    Name =$f[0]
                    version =($f[1] -split "=")[1]
                    Culture =($f[2] -split "=")[1]
                    PublicKeyToken=($f[3] -split "=")[1]
                    Location = $_.Location
                }     
                $obj += New-Object PsObject -Property  $props
            }
$obj | Sort-Object Name | Out-GridView
