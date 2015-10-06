function Get-RssFeed 
{
<#
.SYNOPSIS
Reads RSS feeds from supplied URI and outputs every possible property
.PARAMETER URI 
Parameter supports one or more URIs representing RSS feeds
.EXAMPLE
Get-RSSFeed -uri 'http://powershell.com/cs/blogs/MainFeed.aspx','http://rss.msn.com/' | Out-GridView
Pulls the RSS feed from both msn.com and powershell.com, and displays every available property.
.EXAMPLE
'http://powershell.com/cs/blogs/MainFeed.aspx' | Get-RssFeed | Export-CSV "$env:TEMP\RssFeed.csv" -NoTypeInformation -UseCulture
Pulls the RSS feed from powershell.com using pipeline input, and exports every available property to a csv file.
#>
[CmdLetBinding()]
Param (
    [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
    [string[]]$Uri
)#param
Begin{}#begin
Process {
    foreach ($target in $uri) {
            [xml]$xml=(Invoke-WebRequest -Uri $target -ContentType 'text/xml' -Proxy 'http://sgo-ap060:8080' -ProxyUseDefaultCredentials).Content
            $set=@()
            $xml.rss.channel.item | 
                ForEach-Object {
                            $item=$_
                            if($item.title)
                            {
                                $obj=New-Object PSObject
                                ($xml.rss.channel.item |
                                    Get-Member -MemberType Properties |
                                        Sort-Object -Descending).name | 
                                            ForEach-Object {
                                                    $rssitem=$_
                                                    if ($item.$rssitem.'#text'){$rssvalue=($item.$rssitem.'#text' -join ', ')}#in case there is multiple elements, such as Categories
                                                    else {$rssvalue=$item.$rssitem}
                                                    $obj| Add-Member -MemberType NoteProperty -Name $rssitem -Value $rssvalue
                                            }#ForEach-Object
                                    $set+=$obj
                                }#ForEach-Object
                            }
                  $set
            }#foreach
    }#process
    End{}#end
}#function
