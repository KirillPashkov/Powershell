#requires NLog.dll
$DefaultLoggerName = "$($env:COMPUTERNAME.Split('-')[-1])_Logger"

function New-Logger 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,Position = 0)][Alias('Name')][ValidateScript({
                    $_ -match '[a-zA-Z]|[0-9]|[_]'
        })][string[]]$LoggerName = $DefaultLoggerName,
        [Parameter(Mandatory = $false,Position = 1)][Alias('DLL')][string]$LoggerDLL,
    [Parameter(Mandatory = $false,Position = 2)][Alias('Config')][string]$LoggerConfigFile)
    BEGIN
    { 
        $ModulePath = Get-Module -Name Logger | Select-Object -ExpandProperty ModuleBase
        if (-not($LoggerDLL)) 
        {
            $LoggerDLL = "$ModulePath\NLog.dll"
        }
        if (-not($LoggerConfigFile)) 
        {
            $LoggerConfigFile = "$ModulePath\NLog.config"
        }
        try 
        {
            Add-Type -Path $LoggerDLL -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Ошибка загрузки библиотеки LoggerDLL=$LoggerDLL`n`n$_"
            break
        }
        try 
        {
            [NLog.LogManager]::Configuration = New-Object -TypeName NLog.Config.XmlLoggingConfiguration -ArgumentList ($LoggerConfigFile) -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Ошибка загрузки файла конфигурации LoggerConfigFile=$LoggerConfigFile`n`n$_"
            break
        }
    }
    PROCESS 
    { 
        foreach ($SingeLoggerName in $LoggerName)
        {
            $Command = '$global:'+ "$SingeLoggerName = [NLog.LogManager]::GetLogger('" + $SingeLoggerName + "')"
            try 
            {
                Invoke-Expression -Command $Command -ErrorAction Stop
            }
            catch
            {
                Write-Warning -Message "Ошибка инициализации нового логера`n`n$_`n`nCommand=$Command"
                break
            }
        }
    }
    END
    {Get-ChildItem -Path variable: |
        Where-Object -FilterScript {
            $_.Value -match 'NLog.Logger' -and $_.Name -in $LoggerName
        }|
        ForEach-Object -Process {
            Invoke-Expression -Command $('$' + $($_.Name))
    }}
}

function Get-Logger 
{
    [CmdletBinding()]
    param([Parameter(Mandatory = $false,Position = 0)][Alias('Name')][string]$LoggerName,
    [Parameter(Mandatory = $false,Position = 0)][switch]$DisplayVariableName)
    BEGIN{}
    PROCESS{
        foreach ($ActiveLogger in (Get-ChildItem -Path Variable: | Where-Object -FilterScript {
                    $_.Value -like 'NLog.Logger' -and $_.Name -ne 'Error' -and $_.Name -like "$LoggerName*"
        }).Name)
        {
            if ($DisplayVariableName)
            {
                Write-Output -InputObject $ActiveLogger
            }
            else
            {
                Write-Output -InputObject (Invoke-Expression -Command $('$' + "$ActiveLogger"))
            }
        }
    }
    END{}
}

function Remove-Logger 
{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][AllowNull()][Alias('Name')][string[]]$LoggerName)
    BEGIN{
        $Lookup = Get-ChildItem -Path 'Variable:' | Where-Object -FilterScript {
            $_.Value -like 'NLog.Logger' -and $_.Name -ne '_' -and $_.Name -ne 'PSItem'
        }
        $Object = @()
        foreach ($ItemProperty in $Lookup)
        {
            $Item = New-Object -TypeName PSObject
            $Item | Add-Member -MemberType NoteProperty -Name VariableName -Value $ItemProperty.Name
            $Item | Add-Member -MemberType NoteProperty -Name LoggerName -Value $(Invoke-Expression -Command $('$' + $($ItemProperty.Name))).Name
            $Object += $Item
        }
    }
    PROCESS{
        $LoggerName | ForEach-Object -Process {
            $Piece = $_
            if ($Piece)
            {
                if ($Object)
                {
                    Write-Verbose -Message "Following binding LoggerName=$Piece"
                    $RemoveItem = $Object |
                    Where-Object -FilterScript {
                        $_.LoggerName -like "$Piece*"
                    } |
                    Select-Object -ExpandProperty VariableName
                    if ($RemoveItem)
                    {
                        $RemoveItem | ForEach-Object -Process {
                            Write-Verbose -Message "Removing LoggerVariableName=$_"
                            [void](Remove-Item -Path "Variable:\$_" -Force)
                        }
                    }
                }
            }
        }
    }
    END{}
}

function Set-DetailedLoggerDescription 
{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][ValidateScript({
                    $_ -match '[a-zA-Z]|[0-9]|[_]'
        })][Alias('Description')][string]$FunctionDescription,
    [Parameter(Mandatory = $false,Position = 1,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][Alias('New')][switch]$Start)
    BEGIN{if($Start)
        {
            [void]$($global:Logger = New-Logger)
        }
    }
    PROCESS{
        $FileTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^file'
        }
        $FileTarget | ForEach-Object -Process {
            $_.WrappedTarget.Layout.Text = '${longdate} | ${logger} | ${level:uppercase=true} | ' + $FunctionDescription + ' | ${message}'
        }
        $MailTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^mail'
        }
        $MailTarget.Layout.Text = 'Date: ${longdate}${newline}Computername: ${machinename}${newline}Loggername: ${logger}${newline}' + "CurrentFunction: $FunctionDescription" + '${newline}Errorlevel: ${level:uppercase=true}${newline}Messagetext:${message}'
        $ConsoleTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^coloredConsole'
        }
        $ConsoleTarget.Layout.Text = '${longdate} | ${logger} | ${level:uppercase=true} | ' + $FunctionDescription + ' | ${message} ${onexception:EXCEPTION OCCURRED\:${exception:format=type,message,method:maxInnerExceptionLevel=5:innerFor
        mat=shortType,message,method}}'
    }
    END{}
}

function Set-DefaultLoggerDescription 
{
    [CmdletBinding()]
    param()
    BEGIN{}
    PROCESS{
        $FileTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^file'
        }
        $FileTarget | ForEach-Object -Process {
            $_.WrappedTarget.Layout.Text = '${longdate} | ${logger} | ${level:uppercase=true} | ${message}'
        }
        $MailTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^mail'
        }
        $MailTarget.Layout.Text = 'Date: ${longdate}${newline}Computername: ${machinename}${newline}Loggername: ${logger}${newline}Errorlevel: ${level:uppercase=true}${newline}Messagetext:${message}'
        $ConsoleTarget = $Logger.Factory.Configuration.AllTargets | Where-Object -FilterScript {
            $_.Name -match '^coloredConsole'
        }
        $ConsoleTarget.Layout.Text = '${longdate} | ${logger} | ${level:uppercase=true} | ${message} ${onexception:EXCEPTION OCCURRED\:${exception:format=type,message,method:maxInnerExceptionLevel=5:innerFormat=shortType,message,method}}'
    }
    END{}
}

New-Alias -Name sdld -Value Set-DetailedLoggerDescription

Export-ModuleMember -Function New-Logger, 
Get-Logger, 
Remove-Logger, 
Set-DetailedLoggerDescription, 
Set-DefaultLoggerDescription `
-Variable DefaultLoggerName `
-Alias sdld
