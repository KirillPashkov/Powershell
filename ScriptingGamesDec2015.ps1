$list = @"
1 Partridge in a pear tree
2 Turtle Doves
3 French Hens
4 Calling Birds
5 Golden Rings
6 Geese a laying
7 Swans a swimming
8 Maids a milking
9 Ladies dancing
10 Lords a leaping
11 Pipers piping
12 Drummers drumming
"@
Write-Host '1. sorting by length' -back green
$sorted = $list -split "`n" | Sort-Object Length
$sorted
Write-Host '2. pscustomobject with count and item property AND sorting by length' -back green 
$results = $sorted | % {
    $null = $_ -match '(?<count>[\d]+) (?<item>[^.]+)'
    [PSCustomObject]@{Count=[int]$Matches.Count;Item=$Matches.Item;Len=[int]$Matches.Item.Length;Num=[int]$Matches.Count}}
$results | sort Len,Item | select Count,Item
$i=0
$results | % {if($_.Item -match 'birds|partridge|hens|doves|geese|swans'){[int]$i += $_.Count}}
Write-Host "3. birds count: $i" -back green
$itemscount = ($results | measure -Sum -Property count).sum
Write-Host "4. items count: $itemscount" -back green
$sum=$(1..12 |%{($results | sort Num)[0..($_-1)]}|measure Count -Sum).Sum
Write-Host "number of cumulative gifts: $sum" -back green
