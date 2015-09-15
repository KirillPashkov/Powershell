function Invoke-NotifyIcon 
{
    <#
            .SYNOPSIS
            Displays a NotifyIcon's balloon tip message in the taskbar's notification area.
		
            .DESCRIPTION
            Displays a NotifyIcon's a balloon tip message in the taskbar's notification area.
			
            .PARAMETER NotifyIcon
            The NotifyIcon control that will be displayed.
		
            .PARAMETER BalloonTipText
            Sets the text to display in the balloon tip.
		
            .PARAMETER BalloonTipTitle
            Sets the Title to display in the balloon tip.
		
            .PARAMETER BalloonTipIcon	
            The icon to display in the ballon tip.
		
            .PARAMETER Timeout	
            The time the ToolTip Balloon will remain visible in milliseconds. Default: 0 - Uses windows default.
			
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$BalloonTipText,
        [Parameter(Position = 1)]
        [String]$BalloonTipTitle = '',
        [Parameter(Position = 2)]
        [System.Windows.Forms.ToolTipIcon]$BalloonTipIcon = 'None',
        [Parameter(Position = 3)]
        [int]$Timeout = 0,
        [Parameter(Position = 4)]
        [string]$iconPath
    )
    BEGIN   {
        $NotifyIconObject = New-Object System.Windows.Forms.NotifyIcon
        $NotifyIconObject.Visible = $true
    }
    PROCESS {
        if ($iconPath) 
        {
            $NotifyIconObject.Icon = $iconPath
        }

        if($NotifyIconObject.Icon -eq $null)
        {
            #Set a Default Icon otherwise the balloon will not show
            $NotifyIconObject.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon([System.Windows.Forms.Application]::ExecutablePath)
        }
		
        $NotifyIconObject.ShowBalloonTip($Timeout, $BalloonTipTitle, $BalloonTipText, $BalloonTipIcon)
    }
    END {}
}
