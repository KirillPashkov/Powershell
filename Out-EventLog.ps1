function Out-EventLog 
{
    <#
            .EXAMPLE
            'все пропало' | Out-EventLog -EntryType Error -EventId 666
            .EXAMPLE
            'копирую c:\windows' | Out-EventLog
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0,
                HelpMessage = 'Specify message text.',
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('Text')]
        [string]$Message,

        [Parameter(Mandatory = $false,Position = 1,
                HelpMessage = 'Specify log name.',
        ValueFromPipelineByPropertyName = $true)]
        [string]$LogName = 'PK-Logs',

        [Parameter(Mandatory = $false,Position = 2,
                HelpMessage = 'Specify source name.',
        ValueFromPipelineByPropertyName = $true)]
        [string]$Source = 'Logger',

        [Parameter(Mandatory = $false,Position = 3,
                HelpMessage = 'Specify entry type.',
        ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Error','FailureAudit','Information','SuccessAudit','Warning')]
        [Alias('Type')]
        [string]$EntryType = 'Information',

        [Parameter(Mandatory = $false,Position = 4,
                HelpMessage = 'Specify event id.',
        ValueFromPipelineByPropertyName = $true)]
        [int]$EventId = 1,

        [Parameter(Mandatory = $false,Position = 5,
                HelpMessage = 'Specify computer name.',
        ValueFromPipelineByPropertyName = $true)]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeOutputToConsole

    )
    BEGIN {
        if (-not(Get-WinEvent -ListLog TestTask))
        {
            New-EventLog -LogName TestTask -Source Logger
        }
    } #begin
    PROCESS {
        if ($input -ne $null) 
        {
            $Message = $input
        }
        if ($IncludeOutputToConsole)
        {
            Write-Output -InputObject $Message
        }  
        Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -EventId $EventId -Message $Message -ComputerName $ComputerName -ErrorAction Stop -ErrorVariable err
        if ($err -ne $null)
        {
            Write-Warning -Message "Ошибка записи в журнал $LogName"
        }
    } #process
    END {}
} #function
