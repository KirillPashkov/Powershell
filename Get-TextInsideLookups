function Get-TextInsideLookups
{
    param(
        [String]$InputString,
        [String]$StartLookup,
        [String]$StopLookup
    )

	$Lookup = [System.String]::Format("(?<={0})(.*)(?={1})", $StartLookup, $StopLookup)
	$Text = [regex]::match($InputString,$Lookup).Groups[1].Value
	Write-Output $Text.ToString()
}
