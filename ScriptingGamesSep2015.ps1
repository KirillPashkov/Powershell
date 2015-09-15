ipcsv file.csv|%{gwmi win32_operatingsystem -co $_.MACHINENAME|select @{l='cname';e={$_.__SERVER}},@{l='os';e={$_.Caption}}}|epcsv Output.csv -not
