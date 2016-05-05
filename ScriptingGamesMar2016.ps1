Function Get-Diacritic
{
    Param
    (
        [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_})][String]$Path,
        [Parameter(Mandatory=$True)][String[]]$Recepient,
        [Switch]$AsHTML
    )
    
    $email = @{
    'To' = $Recepient;
    'SmtpServer' = 'mysmtp.server.com';
    'From' = 'powershelldudey';
    'Subject' = "Diacritic files $([datetime]::now)"
    }
        
    [System.Collections.ArrayList]$Files =  gci $Path -Recurse | ? {[int[]][char[]]$_.name -gt 192} | select Name, @{l='Directory'; e={$_.DirectoryName}}, `
                              @{l='Created'; e={$_.CreationTime}}, `
                              @{l='Modified'; e={$_.LastWriteTime}},`
                              @{l='Size'; e={switch ($_.Length){ `
                                    {$_ -lt [math]::pow(2,20)} {"$([math]::Round($_/[math]::pow(2,10),2)) Kb"; break} 
                                    {$_ -lt [math]::pow(2,30)} {"$([math]::Round($_/[math]::pow(2,20),2)) Mb"; break}
                                    {$_ -lt [math]::pow(2,40)} {"$([math]::Round($_/[math]::pow(2,30),2)) GB"; break}
                                    }
                                }
                            } 
    
    if ($files.Count -gt 0){
            $filepath = "$([Environment]::GetEnvironmentVariable('TEMP','Machine'))\$(Get-Date -Format yyyyMMdd)_FileNamesWithDiacritics.csv"
            $files | Export-Csv -Path $filepath
            $email.Add('Attachments',$filepath)
            $email.Add('Body',$files)
            if ($AsHTML){ $email.Add('BodyAsHtml',$true)}
            Send-MailMessage @email
    }
}
