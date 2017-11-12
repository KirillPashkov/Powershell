function ConvertTo-Csv-NoNullorEmptyValues
{
    param($input)
    $input | Where-Object { 
                ($_.PSObject.Properties | 
                    ForEach-Object {$_.Value}) -ne $null -and `
                ($_.PSObject.Properties | 
                    ForEach-Object {$_.Value}) -ne ''
            }
}
$DataSet | ConvertTo-Csv-NoNullorEmptyValues
