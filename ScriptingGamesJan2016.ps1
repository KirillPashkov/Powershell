function Get-Uptime {
    [CmdletBinding()]
param(
[Parameter(Mandatory = $true, ValueFromPipeline = $true)][string[]]$ComputerName=$env:COMPUTERNAME
)
begin
{}
process {
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName[0]
    $connection = Test-Connection $ComputerName -Quiet -Count 1
    if ($connection)
    {
        $wmi = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
        $bootup = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
        $uptime = [System.Math]::Round((New-TimeSpan -Start $bootup -End (Get-Date)).TotalDays,1)
        $status = 'OK'
        if ($bootup -eq $null){$status = 'ERROR'}
        if ($uptime -ge 30){$update = $true}else{$update = $false}
        $obj | Add-Member -MemberType NoteProperty -Name StartTime -Value $bootup
        $obj | Add-Member -MemberType NoteProperty -Name 'Uptime (Days)' -Value $uptime
        $obj | Add-Member -MemberType NoteProperty -Name Status -Value 'OK'
        $obj | Add-Member -MemberType NoteProperty -Name MightNeedPatched $update
    }
    else
    {
        @{StartTime='OFFLINE';'Uptime (Days)'='OFFLINE';Status='OFFLINE';MightNeedPatched='UNKNOWN'} | % {$obj | Add-Member $_}
    }
    $obj
}
end{}
}
