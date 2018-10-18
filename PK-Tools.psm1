#filters
filter Get-Extension
{
param
(
[String[]]
$extension = (‘.bmp’, ’.jpg’, ’.wmv’)
)
    $_ |
    Where-Object {
    $extension -contains $_.Extension
    }
}

#functions
function ConvertPSObjectTo-Hashtable
{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectTo-Hashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectTo-Hashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}

function Get-CurrentUnixTimeStamp {
    [DateTime]$epoch = New-Object System.DateTime 1970, 1, 1, 0, 0, 0, 0, Utc
    [TimeSpan]$diff  = (Get-Date).ToUniversalTime() - $epoch
    return [int64][Math]::Floor($diff.TotalSeconds)
}

function Create-SelfSignedCertificate
{
    [cmdletbinding()]
    Param(
        [string]$Subject
    )

    $subjectDn = new-object -com "X509Enrollment.CX500DistinguishedName"
    $subjectDn.Encode( "CN=" + $subject, $subjectDn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
    $issuer = $Subject
    $issuerDn = new-object -com "X509Enrollment.CX500DistinguishedName"
    $issuerDn.Encode("CN=" + $issuer, $subjectDn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)

    #
    # Create a new Private Key
    $key = new-object -com "X509Enrollment.CX509PrivateKey"
    $key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider"    
    # XCN_AT_SIGNATURE, The key can be used for signing
    $key.KeySpec = 2
    $key.Length = 2048
    # MachineContext 0: Current User, 1: Local Machine
    $key.MachineContext = 1
    $key.Create() 
	 
    #
    # Extended key usage
    $clientAuthOid = New-Object -ComObject "X509Enrollment.CObjectId"
    $clientAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.2")
    $serverAuthOid = new-object -com "X509Enrollment.CObjectId"
    $serverAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuOids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuOids.add($clientAuthOid)
    $ekuOids.add($serverAuthOid)
    $ekuExt = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
    $ekuExt.InitializeEncode($ekuOids)
	
    #
    # Key usage
    $keyUsage = New-Object -com "X509Enrollment.cx509extensionkeyusage"
    # XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE
    $flags = 0x20
    # XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
    $flags = $flags -bor 0x80
    $keyUsage.InitializeEncode($flags)

    #
    # Subject alternative names
    $alternativeNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames"
    $names =  new-object -com "X509Enrollment.CAlternativeNames"
    $name = new-object -com "X509Enrollment.CAlternativeName"
    # Dns Alternative Name
    $name.InitializeFromString(3, "$(hostname)")
    $names.Add($name)
    $alternativeNames.InitializeEncode($names)

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $subjectDn
    $cert.Issuer = $issuerDn
    $cert.NotBefore = (get-date).AddMinutes(-10)
    $cert.NotAfter = $cert.NotBefore.AddYears(1)
    $hashAlgorithm = New-Object -ComObject X509Enrollment.CObjectId
    $hashAlgorithm.InitializeFromAlgorithmName(1,0,0,"SHA256")
    $cert.HashAlgorithm = $hashAlgorithm
    
    $cert.X509Extensions.Add($ekuext)
    $cert.X509Extensions.Add($keyUsage)
    $cert.X509Extensions.Add($alternativeNames)

    $cert.Encode()

    $locator = $(New-Object "System.Guid").ToString()
    $enrollment = new-object -com "X509Enrollment.CX509Enrollment"
    $enrollment.CertificateFriendlyName = $locator
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # Wait for certificate to be populated
    $end = $(Get-Date).AddSeconds(1)
    do {
        $newCert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq $locator })
    } while ($newCert -eq $null -and $(Get-Date) -lt $end)
    $newCert.FriendlyName = ""

    return $newCert     
}

function Get-SystemModuleInformation {
<#
.SYNOPSIS
	Use NtQuerySystemInformation::SystemModuleInformation to get a list of
	loaded modules, their base address and size (x32/x64).
.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.EXAMPLE
	C:\PS> Get-SystemModuleInformation
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct SYSTEM_MODULE_INFORMATION
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
		public UIntPtr[] Reserved;
		public IntPtr ImageBase;
		public UInt32 ImageSize;
		public UInt32 Flags;
		public UInt16 LoadOrderIndex;
		public UInt16 InitOrderIndex;
		public UInt16 LoadCount;
		public UInt16 ModuleNameOffset;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
		internal Char[] _ImageName;
		public String ImageName {
			get {
				return new String(_ImageName).Split(new Char[] {'\0'}, 2)[0];
			}
		}
	}
	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(
			int SystemInformationClass,
			IntPtr SystemInformation,
			int SystemInformationLength,
			ref int ReturnLength);
	}
"@

	echo "`n[+] Calling NtQuerySystemInformation::SystemModuleInformation"

	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		# SystemModuleInformation Class = 11
		$CallResult = [Ntdll]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
		# STATUS_INFO_LENGTH_MISMATCH
		if ($CallResult -eq 0xC0000004) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
		}
		# STATUS_SUCCESS
		elseif ($CallResult -eq 0x00000000) {
			echo "[?] Success, allocated $BuffPtr_Size byte result buffer"
			break
		}
		# Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			echo "[!] Error, NTSTATUS Value: $('{0:X}' -f ($CallResult))`n"
			return
		}
	}

	$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
	$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
	if ([System.IntPtr]::Size -eq 4) {
		$SYSTEM_MODULE_INFORMATION_Size = 284
	} else {
		$SYSTEM_MODULE_INFORMATION_Size = 296
	}

	$BuffOffset = $BuffPtr.ToInt64()
	$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
	$BuffOffset = $BuffOffset + [System.IntPtr]::Size
	echo "[?] Result buffer contains $HandleCount SystemModuleInformation objects"

	$SystemModuleArray = @()
	for ($i=0; $i -lt $HandleCount; $i++){
		$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
		$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_MODULE_INFORMATION)
		
		$HashTable = @{
			ImageName = $Cast.ImageName
			ImageBase = if ([System.IntPtr]::Size -eq 4) {"0x$('{0:X}' -f $($Cast.ImageBase).ToInt32())"} else {"0x$('{0:X}' -f $($Cast.ImageBase).ToInt64())"}
			ImageSize = "0x$('{0:X}' -f $Cast.ImageSize)"
		}
		
		$Object = New-Object PSObject -Property $HashTable
		$SystemModuleArray += $Object
	
		$BuffOffset = $BuffOffset + $SYSTEM_MODULE_INFORMATION_Size
	}

	$SystemModuleArray|Select ImageBase,ImageSize,ImageName |ft -Autosize

	# Free SystemModuleInformation array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
}

function Release-Ref
{
param($Ref)
    ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$Ref) -gt 0)
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

function Get-USBHistory 
{ 
<# 
.SYNOPSIS 
    This fucntion will get the history for USB devices that have been plugged into a machine. 
 
.DESCRIPTION 
     This funciton queries the "SYSTEM\CurrentControlSet\Enum\USBSTOR" key to get a list of all USB storage devices that have 
    been connected to a machine.  The funciton can run against local or remote machines. 
 
.PARAMETER  ComputerName 
    Specifies the computer which you want to get the USB storage device history from.  The value can be a fully qualified domain 
    name or an IP address.  This parameter can be piped to the function.  The local computer is the default. 
 
.Parameter Ping 
    Use Ping to verify a computer is online before connecting to it. 
     
.EXAMPLE 
    PS C:\>Get-USBHistory -ComputerName LAPTOP 
         
    Computer                                                         USBDevice                                                               
    --------                                                         ---------                                                               
    LAPTOP                                                           A-DATA USB Flash Drive USB Device                                       
    LAPTOP                                                           CBM Flash Disk USB Device                                               
    LAPTOP                                                           WD 3200BEV External USB Device                                          
 
    Description 
    ----------- 
    This command displays the history of USB storage device on the localhost. 
         
.EXAMPLE 
    PS C:\>$Servers = Get-Content ServerList.txt 
         
    PS C:\>Get-USBHistory -ComputerName $Servers 
         
         
    Description 
    ----------- 
    This command first creates an array of server names from ServerList.txt then executes the Get-USBHistory script on the array of servers. 
     
.EXAMPLE 
    PS C:\>Get-USBHistory Server1 | Export-CSV -Path C:\Logs\USBHistory.csv -NoTypeInformation 
             
         
    Description 
    ----------- 
    This command gets run the Get-USBHistory command on Server1 and pipes the output to a CSV file located in the C:\Logs directory. 
 
     
.Notes 
LastModified: 7/9/2012 
Author:       Jason Walker 
 
     
#> 
 
 [CmdletBinding()] 
 
Param 
( 
    [parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)] 
    [alias("CN","Computer")] 
    [String[]]$ComputerName=$Env:COMPUTERNAME, 
    [Switch]$Ping     
) 
        
 Begin 
 { 
           
      
     $TempErrorAction = $ErrorActionPreference 
     $ErrorActionPreference = "Stop" 
     $Hive   = "LocalMachine" 
     $Key    = "SYSTEM\CurrentControlSet\Enum\USBSTOR" 
      
  } 
 
  Process 
  {             
     $USBDevices      = @() 
     $ComputerCounter = 0         
         
     ForEach($Computer in $ComputerName) 
     { 
        $USBSTORSubKeys1 = @() 
        $ChildSubkeys    = @() 
        $ChildSubkeys1   = @() 
         
        $ComputerCounter++         
        $Computer = $Computer.Trim().ToUpper() 
        Write-Progress -Activity "Collecting USB history" -Status "Retrieving USB history from $Computer" -PercentComplete (($ComputerCounter/($ComputerName.Count)*100)) 
         
                            
        If($Ping) 
        { 
           If(-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) 
           { 
              Write-Warning "Ping failed on $Computer" 
              Continue 
           } 
        }#end if ping  
                             
         Try 
         { 
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive,$Computer) 
            $USBSTORKey = $Reg.OpenSubKey($Key) 
            $USBSTORSubKeys1  = $USBSTORKey.GetSubKeyNames() 
         }#end try              
         Catch 
         { 
            Write-Warning "There was an error connecting to the registry on $Computer or USBSTOR key not found. Ensure the remote registry service is running on the remote machine." 
         }#end catch 
                 
         ForEach($SubKey1 in $USBSTORSubKeys1) 
         {     
            $ErrorActionPreference = "Continue" 
            $Key2 = "SYSTEM\CurrentControlSet\Enum\USBSTOR\$SubKey1" 
            $RegSubKey2  = $Reg.OpenSubKey($Key2) 
            $SubkeyName2 = $RegSubKey2.GetSubKeyNames() 
 
            $ChildSubkeys   += "$Key2\$SubKeyName2" 
            $RegSubKey2.Close()         
         }#end foreach SubKey1 
          
         ForEach($Child in $ChildSubkeys) 
         { 
                 
            If($Child -match " ") 
            { 
               $BabySubkey = $null 
               $ChildSubkey1 = ($Child.split(" "))[0] 
 
               $SplitChildSubkey1 = $ChildSubkey1.split("\") 
 
               0..4 | Foreach{ [String]$BabySubkey += ($SplitChildSubkey1[$_]) + "\"}  
                        
               $ChildSubkeys1 += $BabySubkey + ($Child.split(" ")[-1]) 
               $ChildSubkeys1 += $ChildSubkey1 
 
            } 
            Else 
            { 
               $ChildSubkeys1 += $Child 
            } 
                $ChildSubKeys1.count 
         }#end foreach ChildSubkeys 
 
         ForEach($ChildSubkey1 in $ChildSubkeys1) 
         {     
            $USBKey      = $Reg.OpenSubKey($ChildSubkey1) 
            $USBDevice   = $USBKey.GetValue('FriendlyName')  
            If($USBDevice) 
            {     
               $USBDevices += New-Object -TypeName PSObject -Property @{ 
                     USBDevice = $USBDevice 
                     Computer  = $Computer 
                     Serial    = $ChildSubkey1.Split("\")[-1] 
                       } 
             } 
                 $USBKey.Close()                                           
          }#end foreach ChildSubKey2 
             
                 $USBSTORKey.Close()            
         #Display results         
     $USBDevices | Select Computer,USBDevice,Serial 
     }#end foreach computer  
               
  }#end process 
                             
  End 
  {         
     #Set error action preference back to original setting         
     $ErrorActionPreference = $TempErrorAction          
  } 
                
}#end function 

function Show-HTML
{
param(
[String]$HTML,
[Int]$Height,
[Int]$Width
)
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]$XAML = @'
    <Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="" WindowStartupLocation="CenterScreen">
            <WebBrowser Name="WebBrowser"></WebBrowser>
    </Window>
'@
    $reader=(New-Object System.Xml.XmlNodeReader $xaml) 
    $Form=[Windows.Markup.XamlReader]::Load( $reader )
    $Form.Width = $Width
    $Form.Height = $Height
    $WebBrowser = $Form.FindName("WebBrowser")
    $WebBrowser.NavigateToString($html)
    [void]$Form.ShowDialog()
}

function ConvertFrom-UnixTime
{ 
param([String]$UnixTime)
    [TimeZone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixTime))
}

function Write-ImageWaterMark 
{ 
#requires -version 2.0 
 
<# 
.Synopsis 
   Write an image as a digital watermark on top of another image 
.Description 
   First create your watermark image. (smaller than target image) 
   Suggest no bigger than 250X50 pixels or you will notice delays. 
   Suggest white image with black or transparent background. 
   The watermark image will become a visible watermark on target. 
   To save into different formats, just specify the extension.   
.Parameter Watermark 
   Enter path to watermark image   
.Parameter SourceImage 
   Enter the path to the original image 
.Parameter TargetImage 
   Enter the path to the target image 
.example 
   Write-ImageWaterMark -watermark "c:\sig.png -SourceImage "c:\source.png" -TargetImage "c:\newimage.jpg"  
 
   Description 
   ----------- 
   newimage.jpg is created using source.png as original and sig.png as watermark image  
.Link 
   http://social.technet.microsoft.com/Profile/en-US/?user=Matthew Painter 
.Link 
   http://gallery.technet.microsoft.com/ScriptCenter/en-us/7bb57644-42ae-4103-843a-6fee3504fdef 
.Link 
   http://gallery.technet.microsoft.com/ScriptCenter/en-us/4789332e-b8f7-4fd0-aa0a-6ad116ea92c7 
.Notes 
   NAME:      Write-ImageWaterMark 
   VERSION:   1.0 
   AUTHOR:    Matthew Painter 
   LASTEDIT:  17/07/2010 
 
#> 
 
   [CmdletBinding()] 
 
   Param ( 
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="A path to original image")] 
      [string]$SourceImage, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="A path to watermark image")] 
      [string]$watermark, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="A path to target image")] 
      [string]$TargetImage, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$False, 
      HelpMessage="Percentage starting point for watermark 0=left 100=right")] 
      [ValidateRange( 0, 100)] 
      [int32]$widthStart=100, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$False, 
      HelpMessage="Percentage starting point for watermark 0=top 100=bottom")] 
      [ValidateRange(0, 100)] 
      [int32]$heightStart=100       
      )       
      
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")   
       
    #load image into memory  
    $i = New-Object System.Drawing.Bitmap $SourceImage 
    $i2=$i 
    $height = $i.height 
    $width = $i.width 
     
    #load watermark into memory  
    $w = New-Object System.Drawing.Bitmap $watermark 
    $wHeight = $w.height 
    $wWidth = $w.width 
     
    #set target pixel location.     
    $xfix=[math]::Floor(($widthStart/100)*$width) 
    if ($xfix -gt $width-$wWidth){$xfix=$width-$wWidth} 
    $yfix=[math]::Floor(($heightStart/100)*$height) 
    if ($yfix -gt $height-$wHeight){$yfix=$height-$wHeight} 
 
    #loop through all pixels in watermark 
    do  
    { 
       for ($x=0; $x -lt $wWidth; $x++) 
       { 
          for ($y=0; $y -lt $wHeight; $y++) 
          { 
             #Get watermark image pixels 
             $wA=$w.getpixel($x, $y).A 
             $wR=$w.getpixel($x, $y).R 
             $wG=$w.getpixel($x, $y).G 
             $wB=$w.getpixel($x, $y).B 
              
             #reduce the brightness of the watermark 
             $o=$wA/255 
             $wR=[math]::Floor($wR/4*$o) 
             $wG=[math]::Floor($wG/4*$o) 
             $wB=[math]::Floor($wB/4*$o) 
              
             #set target area pixels 
             $xt=$xFix+$x 
             $yt=$yFix+$y 
              
             #Get pixels from source image 
             $A=$i.getpixel($xt, $yt).A 
             $R=$i.getpixel($xt, $yt).R 
             $G=$i.getpixel($xt, $yt).G 
             $B=$i.getpixel($xt, $yt).B 
               
             #create new colours  
             $nR=$wR+$R; if ($nR -gt 255){$nR=255} 
             $nG=$wG+$G; if ($nG -gt 255){$nG=255} 
             $nB=$wB+$B; if ($nB -gt 255){$nB=255} 
              
             #add watermark pixels to target image 
             $colour=[System.Drawing.Color]::FromArgb($A,$nR,$nG,$nB) 
             $i2.setpixel($xt,$yt,$colour)          
          } 
       }        
    } 
    until 
    ($wHeight -eq $y -and $wWidth -eq $x)     
 
    $i2.Save($TargetImage) 
     
    $i.dispose() 
    $w.dispose() 
    $i2.dispose() 
     
    [gc]::Collect() 
    [gc]::WaitForPendingFinalizers()     
}

function Write-TextWaterMark 
{ 
#requires -version 2.0 
 
<# 
.Synopsis 
   Write a string of text as a digital watermark on top of your image 
.Description 
   Text string supplied to function is written on top of your image 
   using the predefined font, colour and transparency in script 
   Text is displayed in top left of image (also set in script)    
.Parameter SourceImage 
   Enter the path to the original image 
.Parameter TargetImage 
   Enter the path to the target image 
.Parameter MessageText 
   Text to display on image 
.example 
   Write-TextWaterMark -SourceImage "C:\scripts\original.bmp" -TargetImage "C:\scripts\public.jpg" -MessageText "This image is by Me..."  
 
   Description 
   ----------- 
   Using original.bmp as a template, new file public.jpg is created  
   displaying text "This image is by Me..."  
.Link 
   http://social.technet.microsoft.com/Profile/en-US/?user=Matthew Painter 
.link 
   http://www.snowland.se/2010/03/05/add-text-to-images-with-powershell/ 
.Link 
   http://gallery.technet.microsoft.com/ScriptCenter/en-us/4789332e-b8f7-4fd0-aa0a-6ad116ea92c7 
.Link 
   http://gallery.technet.microsoft.com/ScriptCenter/en-us/7bb57644-42ae-4103-843a-6fee3504fdef 
.Notes 
   NAME:      Write-TextWaterMark 
   VERSION:   1.0 
   AUTHOR:    Matthew Painter 
   LASTEDIT:  18/07/2010 
 
#> 
 
   [CmdletBinding()] 
 
   Param ( 
 
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="A path to original image")] 
      [string]$SourceImage, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="A path to target image")] 
      [string]$TargetImage, 
       
      [Parameter( 
      ValueFromPipeline=$False, 
      Mandatory=$True, 
      HelpMessage="Text to write on image")] 
      [string]$MessageText 
 
      ) 
 
    [Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null 
 
    #read source image and create new target image 
    $srcImg = [System.Drawing.Image]::FromFile($SourceImage) 
    $tarImg = New-Object System.Drawing.Bitmap([int]($srcImg.width)),([int]($srcImg.height)) 
 
    #Intialize Graphics 
    $Image = [System.Drawing.Graphics]::FromImage($tarImg) 
    $Image.SmoothingMode = "AntiAlias" 
 
    $Rectangle = New-Object Drawing.Rectangle 0, 0, $srcImg.Width, $srcImg.Height 
    $Image.DrawImage($srcImg, $Rectangle, 0, 0, $srcImg.Width, $srcImg.Height, ([Drawing.GraphicsUnit]::Pixel)) 
 
    #Write MessageText (10 in from left, 1 down from top, white semi transparent text) 
    $Font = New-Object System.Drawing.Font("Verdana", 24) 
    $Brush = New-Object Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(100, 255, 255,255)) 
    $Image.DrawString($MessageText, $Font, $Brush, 10, 1) 
     
    #Save and close the files 
    $tarImg.save($targetImage, [System.Drawing.Imaging.ImageFormat]::Bmp) 
    $srcImg.Dispose() 
    $tarImg.Dispose() 
}

function New-Shortcut
{
Param(
[String]$SourceFile,
[String]$DestinationFolder,
[String]$ShortcutName=$null,
[String]$Arguments=$null,
[ValidateSet('.lnk','.url')][String]$Extension='.lnk'
)

    if (!(Test-Path $SourceFile))
    {
        Write-Warning "{0} does not exists!" -f $SourceFile
        break
    }
    if (!(Test-Path $DestinationFolder))
    {
        New-Item -ItemType Directory -Path $DestinationFolder -Force
    }
    if ($ShortcutName)
    {
        $ShortcutName = Join-Path $DestinationFolder $ShortcutName
        $ShortcutName = $ShortcutName + $Extension
    }
    else
    {
        $ShortcutName = Join-Path $DestinationFolder ([System.IO.Path]::GetFileNameWithoutExtension($SourceFile))
        $ShortcutName = $ShortcutName + $Extension
    }

    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutName)
    $Shortcut.TargetPath = $SourceFile
    if ($Arguments){$Shortcut.Arguments = "/argument=value"}#$Shortcut.Arguments = "/argument=value"
    $Shortcut.Save()
}

function Get-HostName {
    Param
    (
        [System.Net.IPAddress[]]$IPAddress = '127.0.0.1'
    )
    function CheckDns
    {
        [CmdletBinding()]Param($IP)
        [System.Net.Dns]::GetHostByAddress($IP).HostName

    }
    foreach($IP in $IPAddress)
    {
        $Name = CheckDns -IP $IP -ErrorAction SilentlyContinue
        [pscustomobject]@{Address=$IP;Name=if($Name){$Name}else{'NO DNS RECORDS AVAILABLE'}}
    }
}

function IsNull($Var){[Object]::ReferenceEquals($Var, $null)}

function Invoke-Method
<#
Helper function for PS v2 invoking methods via variables
$Text = 'hello world'
$Method = 'ToUpper'
EXAMPLE 1
Invoke-Method -Object $Text -Method $Method
EXAMPLE 2
Invoke-Method 'hello world' Contains o
#>
{   Param(
        $Object,$Method,$Arguments
    )
    
    if ($Arguments)
    {$Object.PSObject.Methods[$Method].Invoke($Arguments)}
    else
    {$Object.PSObject.Methods[$Method].Invoke()}
}

function Format-Number
{   Param(
    [System.ConsoleColor]$Color = 'Cyan',
    [Switch]$AsArrayElement
    )
    if(-not($AsArrayElement)){$i=1}
    $Input|%{
    Write-Host ("{0}`t:`t" -f [int]$i) -ForegroundColor $Color -NoNewline;
    Write-Host $_
    $i++
    }
}

function Show-Object
{
<#
Here are some examples how to use the new function:
Get-Process -Id $pid | Show-Object
$host | Show-Object
Get-Item -Path $pshome\powershell.exe | Show-Object
#>
param
(
[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
[Object]
$InputObject,
$Title
)
if (!$Title) { $Title = "$InputObject" }
$Form = New-Object System.Windows.Forms.Form
$Form.Size = New-Object System.Drawing.Size @(600,600)
$PropertyGrid = New-Object System.Windows.Forms.PropertyGrid
$PropertyGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
$Form.Text = $Title
$PropertyGrid.SelectedObject = $InputObject
$PropertyGrid.PropertySort = 'Alphabetical'
$Form.Controls.Add($PropertyGrid)
$Form.TopMost = $true
$null = $Form.ShowDialog()
}

function Get-VaultCredential
{
<#
.SYNOPSIS

Displays Windows vault credential objects including cleartext web credentials.

PowerSploit Function: Get-VaultCredential
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-VaultCredential enumerates and displays all credentials stored in the Windows
vault. Web credentials, specifically are displayed in cleartext. This script was
inspired by the following C implementation: http://www.oxid.it/downloads/vaultdump.txt

.EXAMPLE

Get-VaultCredential

.NOTES

Only web credentials can be displayed in cleartext.
#>
    [CmdletBinding()] Param()

    $OSVersion = [Environment]::OSVersion.Version
    $OSMajor = $OSVersion.Major
    $OSMinor = $OSVersion.Minor

    #region P/Invoke declarations for vaultcli.dll
    $DynAssembly = New-Object System.Reflection.AssemblyName('VaultUtil')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('VaultUtil', $False)

    $EnumBuilder = $ModuleBuilder.DefineEnum('VaultLib.VAULT_ELEMENT_TYPE', 'Public', [Int32])
    $null = $EnumBuilder.DefineLiteral('Undefined', -1)
    $null = $EnumBuilder.DefineLiteral('Boolean', 0)
    $null = $EnumBuilder.DefineLiteral('Short', 1)
    $null = $EnumBuilder.DefineLiteral('UnsignedShort', 2)
    $null = $EnumBuilder.DefineLiteral('Int', 3)
    $null = $EnumBuilder.DefineLiteral('UnsignedInt', 4)
    $null = $EnumBuilder.DefineLiteral('Double', 5)
    $null = $EnumBuilder.DefineLiteral('Guid', 6)
    $null = $EnumBuilder.DefineLiteral('String', 7)
    $null = $EnumBuilder.DefineLiteral('ByteArray', 8)
    $null = $EnumBuilder.DefineLiteral('TimeStamp', 9)
    $null = $EnumBuilder.DefineLiteral('ProtectedArray', 10)
    $null = $EnumBuilder.DefineLiteral('Attribute', 11)
    $null = $EnumBuilder.DefineLiteral('Sid', 12)
    $null = $EnumBuilder.DefineLiteral('Last', 13)
    $VAULT_ELEMENT_TYPE = $EnumBuilder.CreateType()

    $EnumBuilder = $ModuleBuilder.DefineEnum('VaultLib.VAULT_SCHEMA_ELEMENT_ID', 'Public', [Int32])
    $null = $EnumBuilder.DefineLiteral('Illegal', 0)
    $null = $EnumBuilder.DefineLiteral('Resource', 1)
    $null = $EnumBuilder.DefineLiteral('Identity', 2)
    $null = $EnumBuilder.DefineLiteral('Authenticator', 3)
    $null = $EnumBuilder.DefineLiteral('Tag', 4)
    $null = $EnumBuilder.DefineLiteral('PackageSid', 5)
    $null = $EnumBuilder.DefineLiteral('AppStart', 100)
    $null = $EnumBuilder.DefineLiteral('AppEnd', 10000)
    $VAULT_SCHEMA_ELEMENT_ID = $EnumBuilder.CreateType()

    $LayoutConstructor = [Runtime.InteropServices.StructLayoutAttribute].GetConstructor([Runtime.InteropServices.LayoutKind])
    $CharsetField = [Runtime.InteropServices.StructLayoutAttribute].GetField('CharSet')
    $StructLayoutCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($LayoutConstructor,
                                                                                     @([Runtime.InteropServices.LayoutKind]::Explicit),
                                                                                     $CharsetField,
                                                                                     @([Runtime.InteropServices.CharSet]::Ansi))
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'

    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.VAULT_ITEM', $StructAttributes, [Object], [System.Reflection.Emit.PackingSize]::Size4)
    $null = $TypeBuilder.DefineField('SchemaId', [Guid], 'Public')
    $null = $TypeBuilder.DefineField('pszCredentialFriendlyName', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pResourceElement', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pIdentityElement', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pAuthenticatorElement', [IntPtr], 'Public')
    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
    {
        $null = $TypeBuilder.DefineField('pPackageSid', [IntPtr], 'Public')
    }
    $null = $TypeBuilder.DefineField('LastModified', [UInt64], 'Public')
    $null = $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public')
    $null = $TypeBuilder.DefineField('dwPropertiesCount', [UInt32], 'Public')
    $null = $TypeBuilder.DefineField('pPropertyElements', [IntPtr], 'Public')
    $VAULT_ITEM = $TypeBuilder.CreateType()

    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.VAULT_ITEM_ELEMENT', $StructAttributes)
    $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)
    $null = $TypeBuilder.DefineField('SchemaElementId', $VAULT_SCHEMA_ELEMENT_ID, 'Public').SetOffset(0)
    $null = $TypeBuilder.DefineField('Type', $VAULT_ELEMENT_TYPE, 'Public').SetOffset(8)
    $VAULT_ITEM_ELEMENT = $TypeBuilder.CreateType()


    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.Vaultcli', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultOpenVault',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Guid].MakeByRefType(),
                                                                 [UInt32],
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultCloseVault',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultFree',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr]),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultEnumerateVaults',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultEnumerateItems',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr],
                                                                 [Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
    {
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultGetItem',
                                                          'vaultcli.dll',
                                                          'Public, Static',
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }
    else
    {
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultGetItem',
                                                          'vaultcli.dll',
                                                          'Public, Static',
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }

    $Vaultcli = $TypeBuilder.CreateType()
    #endregion

    # Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct.
    function local:Get-VaultElementValue
    {
        Param (
            [ValidateScript({$_ -ne [IntPtr]::Zero})]
            [IntPtr]
            $VaultElementPtr
        )

        $PartialElement = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultElementPtr, [Type] $VAULT_ITEM_ELEMENT)
        $ElementPtr = [IntPtr] ($VaultElementPtr.ToInt64() + 16)

        switch ($PartialElement.Type)
        {
            $VAULT_ELEMENT_TYPE::String {
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] $ElementPtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr] $StringPtr)
            }

            $VAULT_ELEMENT_TYPE::Boolean {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Short {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::UnsignedShort {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Int {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::UnsignedInt {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Double {
                [Runtime.InteropServices.Marshal]::PtrToStructure($ElementPtr, [Type] [Double])
            }

            $VAULT_ELEMENT_TYPE::Guid {
                [Runtime.InteropServices.Marshal]::PtrToStructure($ElementPtr, [Type] [Guid])
            }

            $VAULT_ELEMENT_TYPE::Sid {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] $ElementPtr)
                Write-Verbose "0x$($SidPtr.ToString('X8'))"
                $SidObject = [Security.Principal.SecurityIdentifier] ([IntPtr] $SidPtr)
                $SidObject.Value
            }

            # These elements are currently unimplemented.
            # I have yet to see these used in practice.
            $VAULT_ELEMENT_TYPE::ByteArray { $null }
            $VAULT_ELEMENT_TYPE::TimeStamp { $null }
            $VAULT_ELEMENT_TYPE::ProtectedArray { $null }
            $VAULT_ELEMENT_TYPE::Attribute { $null }
            $VAULT_ELEMENT_TYPE::Last { $null }
        }
    }

    $VaultCount = 0
    $VaultGuidPtr = [IntPtr]::Zero
    $Result = $Vaultcli::VaultEnumerateVaults(0, [Ref] $VaultCount, [Ref] $VaultGuidPtr)

    if ($Result -ne 0)
    {
        throw "Unable to enumerate vaults. Error (0x$($Result.ToString('X8')))"
    }

    $GuidAddress = $VaultGuidPtr

    $VaultSchema = @{
        ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
        ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
        ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
        ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
        ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
        ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
        ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
        ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        ([Guid] '00000000-0000-0000-0000-000000000000') = $null
    }

    if ($VaultCount)
    {
        foreach ($i in 1..$VaultCount)
        {
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($GuidAddress, [Type] [Guid])
            $GuidAddress = [IntPtr] ($GuidAddress.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid]))

            $VaultHandle = [IntPtr]::Zero

            Write-Verbose "Opening vault - $($VaultSchema[$VaultGuid]) ($($VaultGuid))"

            $Result = $Vaultcli::VaultOpenVault([Ref] $VaultGuid, 0, [Ref] $VaultHandle)

            if ($Result -ne 0)
            {
                Write-Error "Unable to open the following vault: $($VaultSchema[$VaultGuid]). Error (0x$($Result.ToString('X8')))"
                continue
            }

            $VaultItemCount = 0
            $VaultItemPtr = [IntPtr]::Zero

            $Result = $Vaultcli::VaultEnumerateItems($VaultHandle, 512, [Ref] $VaultItemCount, [Ref] $VaultItemPtr)

            if ($Result -ne 0)
            {
                $null = $Vaultcli::VaultCloseVault([Ref] $VaultHandle)
                Write-Error "Unable to enumerate vault items from the following vault: $($VaultSchema[$VaultGuid]). Error (0x$($Result.ToString('X8')))"
                continue
            }

            $StructAddress = $VaultItemPtr

            if ($VaultItemCount)
            {
                foreach ($j in 1..$VaultItemCount)
                {
                    $CurrentItem = [Runtime.InteropServices.Marshal]::PtrToStructure($StructAddress, [Type] $VAULT_ITEM)
                    $StructAddress = [IntPtr] ($StructAddress.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VAULT_ITEM))

                    $PasswordVaultItem = [IntPtr]::Zero

                    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
                    {
                        $Result = $Vaultcli::VaultGetItem($VaultHandle,
                                                          [Ref] $CurrentItem.SchemaId,
                                                          $CurrentItem.pResourceElement,
                                                          $CurrentItem.pIdentityElement,
                                                          $CurrentItem.pPackageSid,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] $PasswordVaultItem)
                    }
                    else
                    {
                        $Result = $Vaultcli::VaultGetItem($VaultHandle,
                                                          [Ref] $CurrentItem.SchemaId,
                                                          $CurrentItem.pResourceElement,
                                                          $CurrentItem.pIdentityElement,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] $PasswordVaultItem)
                    }

                    $PasswordItem = $null

                    if ($Result -ne 0)
                    {
                        Write-Error "Error occured retrieving vault item. Error (0x$($Result.ToString('X8')))"
                        continue
                    }
                    else
                    {
                        $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordVaultItem, [Type] $VAULT_ITEM)
                    }

                    if ($VaultSchema.ContainsKey($VaultGuid))
                    {
                        $VaultType = $VaultSchema[$VaultGuid]
                    }
                    else
                    {
                        $VaultType = $VaultGuid
                    }

                    if ($PasswordItem.pAuthenticatorElement -ne [IntPtr]::Zero)
                    {
                        $Credential = Get-VaultElementValue $PasswordItem.pAuthenticatorElement
                    }
                    else
                    {
                        $Credential = $null
                    }

                    $PackageSid = $null

                    if ($CurrentItem.pPackageSid -and ($CurrentItem.pPackageSid -ne [IntPtr]::Zero))
                    {
                        $PackageSid = Get-VaultElementValue $CurrentItem.pPackageSid
                    }


                    $Properties = @{
                        Vault = $VaultType
                        Resource = if ($CurrentItem.pResourceElement) { Get-VaultElementValue $CurrentItem.pResourceElement } else { $null }
                        Identity = if ($CurrentItem.pIdentityElement) { Get-VaultElementValue $CurrentItem.pIdentityElement } else { $null }
                        PackageSid = $PackageSid
                        Credential = $Credential
                        LastModified = [DateTime]::FromFileTimeUtc($CurrentItem.LastModified)
                    }

                    $VaultItem = New-Object PSObject -Property $Properties
                    $VaultItem.PSObject.TypeNames[0] = 'VAULTCLI.VAULTITEM'

                    $VaultItem

                    $null = $Vaultcli::VaultFree($PasswordVaultItem)
                }
            }

            $null = $Vaultcli::VaultCloseVault([Ref] $VaultHandle)
        }
    }
}

function Get-RandomDateTime
{
    Param(
        [ValidateRange(1970,2100)][String]$FromYear=1970,
        [ValidateRange(1970,2100)][String]$ToYear=2100,
        [Int]$NumberValues=1
        )
    1..$NumberValues | % {
    $Month = Get-Random -Minimum 1 -Maximum 12
    $Year = Get-Random -Minimum (Get-Date -Year $FromYear).Year -Maximum (Get-Date -Year $ToYear).Year
    $Day = Get-Random -Minimum 1 -Maximum ([DateTime]::DaysInMonth($Year, $Month))
    $Hour = Get-Random -Minimum 0 -Maximum 24
    $Minute = Get-Random -Minimum 0 -Maximum 60
    $Second = Get-Random -Minimum 0 -Maximum 60
    Get-Date -Year $Year -Month $Month -Day $Day -Hour $Hour -Minute $Minute -Second $Second
    }
}

function Invoke-ChangeDataTableColumnType
{
[CmdletBinding()]
[OutputType([System.Data.DataTable])]
    Param(
    [System.Data.DataTable]$DataTable,
    [String]$ColumnName,
    [ValidateSet('String','Int','DateTime')][String]$NewType
    )
    if ($DataTable.Columns.ColumnName -contains $ColumnName)
    {
        [System.Data.DataTable]$NewTable = $dt.Clone();
        $NewTable.Columns[$ColumnName].DataType = $NewType
        foreach ($Row in $DataTable)
        {
            $NewTable.ImportRow($Row);
        }
        ,$NewTable
    }
    else
    {
        Write-Warning "$ColumnName column in DataTable were not found";
        break;
    }
}

function Import-FilesToDB
{
#Import-FilesToDB -RootDirectory 'C:\temp\Toad for Oracle 12.5\Toad for Oracle 12.5' -Verbose
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][ValidateScript({Test-Path $_})][String[]]$RootDirectory=(Join-Path $env:USERPROFILE 'Documents\PowerShell'),
[Parameter(Mandatory = $false,Position = 1)][String]$DBFilesRootDirectory='C:\temp\',
[Parameter(Mandatory = $false,Position = 2)][String]$DBName,
[Parameter(Mandatory = $false,Position = 3)][Int]$DBFileSizeMB=1500,
[Parameter(Mandatory = $false,Position = 4)][Int]$DBLogSizeMB=100,
[Parameter(Mandatory = $false,Position = 5)][String[]]$ExcludeExtenstions=@('*.wmv','*.msu','*.flv','*.avi')
)
cls

[array]$Files = Get-ChildItem $RootDirectory -Recurse -Exclude $ExcludeExtenstions | 
? {$_.PSIsContainer -eq $false} | 
Select -ExpandProperty FullName

[array]$ExcludedFiles = Get-ChildItem $RootDirectory -Recurse -Include $ExcludeExtenstions | 
? {$_.PSIsContainer -eq $false} | 
Select -ExpandProperty FullName

if (-not($DBName)){$DBName='files_' + $($Files.Count).ToString() + '_' + $(Get-Date -f ddMMyy)}
Write-Verbose "Параметры БД:`n`nИмя`t$DBName`nРазмер файла данных`t$($DBFileSizeMB)MB`nРазмер файла лога`t$($DBLogSizeMB)MB`nРасположение файлов БД`t$DBFilesRootDirectory`n`n"
$Info = "Директории:`n`n"
$Info += foreach ($Directory in $Paths){"{0}`n" -f $Directory}
$Info += "`nИсключенные расширения файлов`t$ExcludeExtenstions`n`n"
Write-Verbose $Info

Remove-Item $(Join-Path $DBFilesRootDirectory 'LOG.log') -Force -ErrorAction SilentlyContinue

if ((Get-Service MSSQLSERVER | Select -ExpandProperty Status) -ne 'Running')
{
    try
    {
        Stop-Service MSSQLSERVER -Force -Verbose
        Start-Service MSSQLSERVER -Verbose
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
        break
    }
}

if (-not (Test-Path $DBFilesRootDirectory))
{
    try
    {
        $null = New-Item -Path $Path -ItemType Directory -Force -ErrorVariable Directory
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
        break
    }
}

$RemoveExisting = @"
IF EXISTS(SELECT * FROM sysdatabases where name = N'$($DBName)')
DROP DATABASE $DBName
"@

$Create_DB = @"
CREATE DATABASE $DBName
ON PRIMARY (
NAME = $($DBName)_dat,
FILENAME = '$(Join-Path $DBFilesRootDirectory $DBName).mdf',
SIZE = $($DBFileSizeMB)MB,
MAXSIZE = UNLIMITED,
FILEGROWTH = 50MB)
LOG ON (
NAME  = $($DBName)_log,
FILENAME = '$(Join-Path $DBFilesRootDirectory $DBName).ldf',
SIZE  = $($DBLogSizeMB)MB,
MAXSIZE = UNLIMITED,
FILEGROWTH = 10MB);
"@

$Queries = @(
@"
EXEC sp_configure 'default language', 21;
RECONFIGURE;
SET DATEFORMAT dmy;
"@,
@"
CREATE TABLE dbo.Files
(
	File_Id int identity(1,1) primary key,
	Attachment nvarchar(255)default null,
	AttachmentFile varbinary(max) default null,
	Size as CAST(CAST(ROUND((DATALENGTH(AttachmentFile) / 1048576.0),18) AS DECIMAL(6,18)) AS nvarchar(max)) PERSISTED,
	InsertTime datetime default getdate() not null,
	SystemUser nvarchar(25) default SYSTEM_USER not null
);
"@,
@"
CREATE TABLE dbo.ExcludedFiles
(
	File_Id int identity(1,1) primary key,
    FullName nvarchar(255) null,
	SizeMB nvarchar(255) null
);
"@,
@"
SET NUMERIC_ROUNDABORT OFF;
SET ANSI_PADDING,
    ANSI_WARNINGS,
    CONCAT_NULL_YIELDS_NULL,
    ARITHABORT,
    QUOTED_IDENTIFIER,
    ANSI_NULLS ON;
"@,
@"
CREATE VIEW dbo.Files_V
WITH SCHEMABINDING AS
	Select 
		File_Id,
		SystemUser,
		Attachment,
		Size
	from dbo.Files;
"@,
@"
CREATE UNIQUE CLUSTERED INDEX IDX_RecordsView
ON dbo.Files_V(File_Id);
"@)

try
{
    Write-Verbose 'Удаляю БД в случае если она уже существует..'
    $($((Get-Date).ToString()) + "`t" + 'EXECUTING ' + "`n`n" + $RemoveExisting + "`n`n")| Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    Invoke-SQLServer -Query $RemoveExisting
    $($((Get-Date).ToString()) + "`t" + 'SUCCESS' + "`n`n") | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
}
catch
{
    $((Get-Date).ToString()) + "`t$($Error[0].Exception.Message)`n`n" | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    break
}

try
{
    Write-Verbose 'Создание БД..'
    $($((Get-Date).ToString()) + "`t" + 'EXECUTING ' + "`n`n" + $Create_DB + "`n`n")| Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    Invoke-SQLServer -Query $Create_DB
    $($((Get-Date).ToString()) + "`t" + 'SUCCESS' + "`n`n") | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
}
catch
{
    $((Get-Date).ToString()) + "`t$($Error[0].Exception.Message)`n`n" | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    break
}

foreach ($Query in $Queries)
{
    try
    {
        Write-Verbose 'Создание объектов БД..'
        $($((Get-Date).ToString()) + "`t" + 'EXECUTING ' + "`n`n" + $Query + "`n`n") | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
        Invoke-SQLServer -Query $Query -DefaultDatabase $DBName
        $($((Get-Date).ToString()) + "`t" + 'SUCCESS' + "`n`n") | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    }
    catch
    {
        $((Get-Date).ToString()) + "`t$($Error[0].Exception.Message)`n`n" | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
        break
    }
}

$i=1
$e=0
Write-Verbose "Количество исключенных файлов $($ExcludedFiles.Count)"
Write-Verbose 'Загрузка информации об исключенных файлов в БД..'
foreach ($File in $ExcludedFiles)
{

Write-Progress -Activity 'Загрузка информации об исключенных файлов в БД...' `
               -CurrentOperation "`t$File" `
               -Status "`t`Файл`t($($i)/$($Files.Count))`t" `
               -PercentComplete (($i / $Files.Count) * 100)

$InsertQuery = @"
    INSERT INTO [$($DBName)].dbo.ExcludedFiles(FullName,SizeMB)
    VALUES
    (
    N'$($File -replace "'","''")',
    N'$(Get-Item $File | Select @{n='Size';e={$_.Length / 1MB}} | Select -ExpandProperty Size)'
    )
"@
    try
    {
        Invoke-SQLServer -Query $InsertQuery -DefaultDatabase $DBName -QueryTimeout 0
        $($((Get-Date).ToString()) + "`tSUCCESS`t" + $File + "`t" + 'Файл добавлен') | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    }
    catch
    {
        $($((Get-Date).ToString()) + "`tERROR`t" + $File + "`t" + $Error[0].Exception.Message) | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
        $e++
    }
    $i++
}

Write-Verbose "Найдено файлов для загрузки: $($Files.Count)"
Write-Verbose 'Выполняется загрузка..'
$i=1
$e=0
foreach ($File in $Files)
{

Write-Progress -Activity 'Загрузка файлов в БД...' `
               -CurrentOperation "`t$File" `
               -Status "`t`Файл`t($($i)/$($Files.Count))`t" `
               -PercentComplete (($i / $Files.Count) * 100)

$InsertQuery = @"
    INSERT INTO [$($DBName)].dbo.Files(Attachment,AttachmentFile)
    SELECT
    N'$($File -replace "'","''")',
    AttachmentFile.*
    FROM
    OPENROWSET(BULK N'$($File -replace "'","''")', SINGLE_BLOB) as AttachmentFile
"@
    try
    {
        Invoke-SQLServer -Query $InsertQuery -DefaultDatabase $DBName -QueryTimeout 0
        $($((Get-Date).ToString()) + "`tSUCCESS`t" + $File + "`t" + 'Файл добавлен') | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
    }
    catch
    {
        $($((Get-Date).ToString()) + "`tERROR`t" + $File + "`t" + $Error[0].Exception.Message) | Out-File $(Join-Path $DBFilesRootDirectory 'LOG.log') -Append
        $e++
    }
    $i++
}
Write-Verbose "Количество ошибок во время загрузки файлов $e / $($Files.Count)"
[System.GC]::Collect()
}

function Export-FilesFromDB
{
#Export-FilesFromDB -DBName files_667_130716 -Verbose
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][ValidateScript({Test-Path $_})][String]$RootUpload = (Join-Path $env:TEMP 'Upload'),
[Parameter(Mandatory = $true,Position = 1)][String]$DBName
)
cls

$DBCheck = Invoke-SQLServer -Query "if db_id('$DBName') is not null select 1"
if (-not($DBCheck))
{
    Write-Warning "БД $DBName не найдена"
    break
}

$DataCount = Invoke-SQLServer -Query "select count(*) from $DBName.dbo.Files" | Select -ExpandProperty Column1
1..$DataCount | % {
    $Item = $_
    $Row=Invoke-SQLServer -Query "select Attachment,AttachmentFile,Size from $DBName.dbo.Files where File_Id = $Item"

    $Path = Join-Path $RootUpload (Split-Path $Row.Attachment -NoQualifier)

    Write-Progress -Activity "Получения данных`t($Item)/$($DataCount))`t" `
                   -CurrentOperation "`t$($Row.Size) MB`t"`
                   -Status "`tЭкспорт файла`t$Path`t" `
                   -PercentComplete (($Item / $DataCount) * 100)

    if (-not(Test-Path (Split-Path $Path -Parent)))
    {
        [void](New-Item -Path $(Split-Path $Path -Parent) -ItemType Directory -Force)
        Write-Verbose "Директория создана: $(Split-Path $Path -Parent)"
        Start-Sleep -Milliseconds 100
    }
    try
    {
        [byte[]]$bytes=$null
        [byte[]]$bytes=$($Row | Select-Object -ExpandProperty AttachmentFile)
        [System.IO.File]::WriteAllBytes($Path, $bytes)
        #$FS=New-Object IO.FileStream $Path ,'Append','Write','Read'
        #$FS.WriteAsync($Row.AttachmentFile,0,$Row.AttachmentFile.Length) | Out-Null
        #$FS.Close()
        #$FS.Dispose()
        #$FS=$null
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        Start-Sleep -Milliseconds 100
    }
    catch #[System.OutOfMemoryException]
    {
        $Error[0]
        $Row
    }
}
$ps = New-Object System.Diagnostics.ProcessStartInfo
$ps.FileName = 'explorer'
$ps.Arguments = '/select, ' + $RootUpload
[Void][System.Diagnostics.Process]::Start($ps)
}

function Invoke-BackupDB
{
#Invoke-BackupDB -DBName files_667_130716 -Verbose
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][String]$RootDirectory = 'C:\DBBackup\',
[Parameter(Mandatory = $true,Position = 1)][String]$DBName,
[Parameter(Mandatory = $false,Position = 2)][Switch]$NoExtension
)
cls

$DBCheck = Invoke-SQLServer -Query "if db_id('$DBName') is not null select 1"
if (-not($DBCheck))
{
    Write-Warning "БД $DBName не найдена"
    break
}

if (-not (Test-Path $RootDirectory))
{
    try
    {
        $null = New-Item -Path $RootDirectory -ItemType Directory -Force -ErrorVariable Directory
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
        break
    }
}
$Backup = Join-Path $RootDirectory $DBName
if (-not($NoExtension)){$Backup += '.bak'}

try
{
    if (Test-Path $Backup)
    {
        Remove-Item $Backup -Force
    }
    Write-Verbose "Выполняется ""backup database $DBName to disk = '$Backup' with compression"""
    Invoke-SQLServer -Query "backup database $DBName to disk = '$Backup' with compression"
    Write-Verbose "Создание резервной копии завершено"
}
catch
{
    Write-Warning $($Error[0].Exception.Message)
    break
}
$ps = New-Object System.Diagnostics.ProcessStartInfo
$ps.FileName = 'explorer'
$ps.Arguments = '/select, ' + $Backup
[Void][System.Diagnostics.Process]::Start($ps)
}

function Invoke-RestoreDB
{
#Invoke-RestoreDB -BackupFile 'C:\DBBackup\files_667_130716.bak' -DBName MyFilesDB -RemoveBackupFileUponSuccessfullRestore -Verbose
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][ValidateScript({Test-Path $_})][String]$DBFilesRootDirectory='C:\temp\',
[Parameter(Mandatory = $true,Position = 1)][ValidateScript({Test-Path $_})][String]$BackupFile,
[Parameter(Mandatory = $true,Position = 2)][String]$DBName,
[Parameter(Mandatory = $false,Position = 3)][Switch]$RemoveBackupFileUponSuccessfullRestore
)
    cls
    $DBCheck = Invoke-SQLServer -Query "if db_id('$DBName') is not null select 1"
    if ($DBCheck)
    {
        Write-Warning "БД $DBName уже существует"
        break
    }
    Write-Verbose "Анализ файла резервной копии БД $BackupFile"
    try
    {
        $Files = @(Invoke-SQLServer "restore filelistonly from disk = '$BackupFile'" | Select -ExpandProperty LogicalName)
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
        break
    }
    $Data = $Files | ? {$_ -like '*_dat'}
    $Log = $Files | ? {$_ -like '*_log'}
    $MDF = $(Join-Path $DBFilesRootDirectory $DBName) + '.mdf'
    $LDF = $(Join-Path $DBFilesRootDirectory $DBName) + '.ldf'
    if (Test-Path $MDF){Remove-Item $MDF -Force}
    if (Test-Path $LDF){Remove-Item $LDF -Force}
    Write-Verbose "Выполняется ""restore database $DBName from disk = '$BackupFile' with move '$Data' to '$($MDF)', move '$Log' TO '$($LDF)'"""
    try
    {
        Invoke-SQLServer -Query "restore database $DBName from disk = '$BackupFile' with move '$Data' to '$($MDF)', move '$Log' TO '$($LDF)'" -Timeout 0
        Write-Verbose "Восстановление БД завершено успешно"
        if ($RemoveBackupFileUponSuccessfullRestore)
        {
            Remove-Item $BackupFile -Force | Out-Null
            Write-Verbose "Файл удален $BackupFile"
        }
    }
    catch
    {
        Write-Warning $($Error[0].Exception)
        break
    }
}

function ConvertTo-DataTable
{
 <#
 .EXAMPLE
 $DataTable = ConvertTo-DataTable $Source
 .PARAMETER Source
 An array that needs converted to a DataTable object
 #>
[CmdLetBinding(DefaultParameterSetName="None")]
param(
 [Parameter(Position=0,Mandatory=$true)][System.Array]$Source,
 [Parameter(Position=1,ParameterSetName='Like')][String]$Match=".+",
 [Parameter(Position=2,ParameterSetName='NotLike')][String]$NotMatch=".+"
)
if ($NotMatch -eq ".+"){
$Columns = $Source[0] | Select * | Get-Member -MemberType NoteProperty | Where-Object {$_.Name -match "($Match)"}
}
else {
$Columns = $Source[0] | Select * | Get-Member -MemberType NoteProperty | Where-Object {$_.Name -notmatch "($NotMatch)"}
}
$DataTable = New-Object System.Data.DataTable
foreach ($Column in $Columns.Name)
{
 $DataTable.Columns.Add("$($Column)") | Out-Null
}
#For each row (entry) in source, build row and add to DataTable.
foreach ($Entry in $Source)
{
 $Row = $DataTable.NewRow()
 foreach ($Column in $Columns.Name)
 {
 $Row["$($Column)"] = if($Entry.$Column -ne $null){($Entry | Select-Object -ExpandProperty $Column) -join ', '}else{$null}
 }
 $DataTable.Rows.Add($Row)
}
#Validate source column and row count to DataTable
if ($Columns.Count -ne $DataTable.Columns.Count){
 throw "Conversion failed: Number of columns in source does not match data table number of columns"
}
else{ 
 if($Source.Count -ne $DataTable.Rows.Count){
 throw "Conversion failed: Source row count not equal to data table row count"
 }
 #The use of "Return ," ensures the output from function is of the same data type; otherwise it's returned as an array.
 else{
 Return ,$DataTable
 }
 }
}

function Set-FilePath
{
#Set-FilePath -Multiselect True -Filter 'Text files|*.txt'
[CmdletBinding()]
param(
[String]$Filter = 'All Files|*.*',
[ValidateSet($true,$false)][String]$Multiselect = $false
)
[System.Windows.Forms.Application]::EnableVisualStyles()
$OpenFileDialog = New-Object 'System.Windows.Forms.OpenFileDialog'
$OpenFileDialog.Filter = $Filter
$OpenFileDialog.Multiselect = $Multiselect
    if ($OpenFileDialog.ShowDialog() -eq 'OK')
    { 
        if ($Multiselect -eq $true)
        { $OpenFileDialog.FileNames }
        else
        { $OpenFileDialog.FileName }
    }
}

function Invoke-SiebelSrvMgrCmd {
[CmdletBinding()]
param(
[Parameter(Mandatory = $true,Position = 0)][ValidateScript({$_ -ne $null -and $_ -ne ''})][String]$Command,
[Parameter(Mandatory = $false,Position = 1)][String]$BinaryHome,
[Parameter(Mandatory = $false,Position = 2)][String]$GatewayServer,
[Parameter(Mandatory = $false,Position = 3)][String]$Enterprise,
[Parameter(Mandatory = $false,Position = 4)][String]$User,
[Parameter(Mandatory = $false,Position = 5)][String]$Password,
[Parameter(Mandatory = $false,Position = 6)][Switch]$RawOutput,
[Parameter(Mandatory = $false,Position = 7)][Switch]$OutputAsTable,
[Parameter(Mandatory = $true,Position = 8)][ValidateSet('CRMUL','CIFUL','OCRMFL')][String]$RSHB_Siebel
)
    switch ($RSHB_Siebel)
    {
        'CRMUL'
        {
            $BinaryHome=(Join-Path $env:USERPROFILE 'Documents\Work\Siebel\SRVMGR\CRMUL')
            $GatewayServer='sgo-ap277'
            $Enterprise='PROD'
        }

        'CIFUL'
        {
            $BinaryHome=(Join-Path $env:USERPROFILE 'Documents\Work\Siebel\SRVMGR\CIFUL')
            $GatewayServer='sgo-gw009'
            $Enterprise='CIF_PROD'
        }
        'OCRMFL'
        {
            $BinaryHome=(Join-Path $env:USERPROFILE 'Documents\Work\Siebel\SRVMGR\OCRMFL')
            $GatewayServer='SGO-GW011'
            $Enterprise='SBA_82'
        }
    }

    try 
        {
            if (!(Test-Path ($BinaryHome +'\srvrmgr.exe')))
            {
                Write-Warning ('No ' + $BinaryHome +'\srvrmgr.exe found.')
                break
            }
            $siebel = $BinaryHome + '\srvrmgr.exe /g ' + $GatewayServer + ' /e ' + $Enterprise + ' /u ' + $User + ' /p ' + $Password + " /c '" + $Command + "'"
            Write-Verbose "Executing $siebel"
            $resultset = iex $siebel
            if ($RawOutput)
            {
                Write-Output $resultset
                break
            }
            if ($command -notlike 'help *' -and $command -notlike 'set *' -and $command -notlike 'change *')
            {
                $crop = $resultset.Count-4
                $header = $resultset[24] -split' '|?{$_}
                $delimiter = $resultset[25]-split'  '|?{$_}|%{$_.Length+2}
                $delimiter = $delimiter[0..$($delimiter.Count-1)]
                $fresultset = $resultset[26..$crop]
                $obj_array = @()
                $fresultset|?{$_}| % {
                    $resultset_item = $_
                    $fe=0
                    $h=0
                    $obj=New-Object PSObject
                    $delimiter| % {
                        $delimiter_item=$_
                        if ($fe-eq0)
                        { $value=$resultset_item.Remove($delimiter_item).Trim() }
                        elseif($fe-lt($resultset_item.Length-$delimiter[-1]))
                        { $value=$resultset_item.Remove(0,$fe).Remove($delimiter_item).Trim() }
                        else
                        { $value=$resultset_item.Remove(0,$fe).Trim() }
                        $fe+=$delimiter_item
                        $obj | Add-Member -MemberType NoteProperty -Name $header[$h] -Value $value
                        $h++
                    }
                    if ($obj -ne $null){$obj_array+=$obj}
                }
                    if ($OutputASTable)
                    {Write-Output $obj_array|ft -Wrap -AutoSize}
                    else
                    {Write-Output $obj_array}
            }
            else
            {
                $resultset[22..($resultset.Count-3)]
            }
        }
        catch
        {
            #Write-Error $Error[0].Exception.Message
        }
}

function Set-ReverseString
{
[CmdletBinding()]
param(
[Parameter(Mandatory = $true,Position = 0)][String]$String)
$Text = $String
$Text = $Text.ToCharArray()
[Array]::Reverse($text)
-join $text
}

function Invoke-MessageBox
{
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][String]$Text='Text',
[Parameter(Mandatory = $false,Position = 1)][String]$Caption='Caption'
)
[void][System.Windows.Forms.MessageBox]::Show($Text,$Caption)
}

function Set-WindowStyle
{
[CmdletBinding()]
param(
[Parameter(Mandatory = $false,Position = 0)][Int][ValidateRange(1,50)]$Throttle=10,
[Parameter(Mandatory = $false,Position = 1)][ValidateSet('FORCEMINIMIZE','HIDE','MAXIMIZE','MINIMIZE','RESTORE', 
'SHOW','SHOWDEFAULT','SHOWMAXIMIZED','SHOWMINIMIZED','SHOWMINNOACTIVE','SHOWNA','SHOWNOACTIVATE','SHOWNORMAL')]$Style = 'MINIMIZE',
[Parameter(Mandatory = $false,Position = 2)][Int[]]$Applications = @(Get-Process | ? {$_.MainWindowTitle.length -ne 0} | % {$_[0].MainWindowHandle})
)

$WindowStates = @{
    'FORCEMINIMIZE'   = 11
    'HIDE'            = 0
    'MAXIMIZE'        = 3
    'MINIMIZE'        = 6
    'RESTORE'         = 9
    'SHOW'            = 5
    'SHOWDEFAULT'     = 10
    'SHOWMAXIMIZED'   = 3
    'SHOWMINIMIZED'   = 2
    'SHOWMINNOACTIVE' = 7
    'SHOWNA'          = 8
    'SHOWNOACTIVATE'  = 4
    'SHOWNORMAL'      = 1
}

    $ScriptBlock = {
       Param([int]$Application)
       $Code = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
       Add-Type -MemberDefinition $Code -Name NativeMethods -Namespace Win32
       [void][Win32.NativeMethods]::ShowWindowAsync($Application,$WindowStates[$Style])
    }
 
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
    $RunspacePool.Open()
    $Jobs = @()
 
    $Applications = Get-Process | ? {$_.MainWindowTitle.length -ne 0} | % {$_[0].MainWindowHandle}
    $Applications | % {
       $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($_)
       $Job.RunspacePool = $RunspacePool
       [void]$Job.BeginInvoke()
    }
}

function Convert-HexToNetmask
{
param(
[Parameter(Mandatory=$true)][string]$Hex,
[Parameter(Mandatory=$false)][switch]$NoPrefix
)

if (-not($NoPrefix))
{$Hex='0x'+$Hex}

Write-Verbose "Hex is set to $Hex"

    switch ($Hex)
    {
        '0x00000000' {$cidr='/0';$network='0.0.0.0';$binary='00000000 00000000 00000000 00000000'}
        '0x80000000' {$cidr='/1';$network='128.0.0.0';$binary='10000000 00000000 00000000 00000000'}
        '0xc0000000' {$cidr='/2';$network='192.0.0.0';$binary='11000000 00000000 00000000 00000000'}
        '0xe0000000' {$cidr='/3';$network='224.0.0.0';$binary='11100000 00000000 00000000 00000000'}
        '0xf0000000' {$cidr='/4';$network='240.0.0.0';$binary='11110000 00000000 00000000 00000000'}
        '0xf8000000' {$cidr='/5';$network='248.0.0.0';$binary='11111000 00000000 00000000 00000000'}
        '0xfc000000' {$cidr='/6';$network='252.0.0.0';$binary='11111100 00000000 00000000 00000000'}
        '0xfe000000' {$cidr='/7';$network='254.0.0.0';$binary='11111110 00000000 00000000 00000000'}
        '0xff000000' {$cidr='/8';$network='255.0.0.0';$binary='11111111 00000000 00000000 00000000'}
        '0xff800000' {$cidr='/9';$network='255.128.0.0';$binary='11111111 10000000 00000000 00000000'}
        '0xffc00000' {$cidr='/10';$network='255.192.0.0';$binary='11111111 11000000 00000000 00000000'}
        '0xffe00000' {$cidr='/11';$network='255.224.0.0';$binary='11111111 11100000 00000000 00000000'}
        '0xfff00000' {$cidr='/12';$network='255.240.0.0';$binary='11111111 11110000 00000000 00000000'}
        '0xfff80000' {$cidr='/13';$network='255.248.0.0';$binary='11111111 11111000 00000000 00000000'}
        '0xfffc0000' {$cidr='/14';$network='255.252.0.0';$binary='11111111 11111100 00000000 00000000'}
        '0xfffe0000' {$cidr='/15';$network='255.254.0.0';$binary='11111111 11111110 00000000 00000000'}
        '0xffff0000' {$cidr='/16';$network='255.255.0.0';$binary='11111111 11111111 00000000 00000000'}
        '0xffff8000' {$cidr='/17';$network='255.255.128.0';$binary='11111111 11111111 10000000 00000000'}
        '0xffffc000' {$cidr='/18';$network='255.255.192.0';$binary='11111111 11111111 11000000 00000000'}
        '0xffffe000' {$cidr='/19';$network='255.255.224.0';$binary='11111111 11111111 11100000 00000000'}
        '0xfffff000' {$cidr='/20';$network='255.255.240.0';$binary='11111111 11111111 11110000 00000000'}
        '0xfffff800' {$cidr='/21';$network='255.255.248.0';$binary='11111111 11111111 11111000 00000000'}
        '0xfffffc00' {$cidr='/22';$network='255.255.252.0';$binary='11111111 11111111 11111100 00000000'}
        '0xfffffe00' {$cidr='/23';$network='255.255.254.0';$binary='11111111 11111111 11111110 00000000'}
        '0xffffff00' {$cidr='/24';$network='255.255.255.0';$binary='11111111 11111111 11111111 00000000'}
        '0xffffff80' {$cidr='/25';$network='255.255.255.128';$binary='11111111 11111111 11111111 10000000'}
        '0xffffffc0' {$cidr='/26';$network='255.255.255.192';$binary='11111111 11111111 11111111 11000000'}
        '0xffffffe0' {$cidr='/27';$network='255.255.255.224';$binary='11111111 11111111 11111111 11100000'}
        '0xfffffff0' {$cidr='/28';$network='255.255.255.240';$binary='11111111 11111111 11111111 11110000'}
        '0xfffffff8' {$cidr='/29';$network='255.255.255.248';$binary='11111111 11111111 11111111 11111000'}
        '0xfffffffc' {$cidr='/30';$network='255.255.255.252';$binary='11111111 11111111 11111111 11111100'}
        '0xfffffffe' {$cidr='/31';$network='255.255.255.254';$binary='11111111 11111111 11111111 11111110'}
        '0xffffffff' {$cidr='/32';$network='255.255.255.255';$binary='11111111 11111111 11111111 11111111'}
        default {$cidr='N\A';$network='N\A';$binary='N\A'}
    }
    [PSCustomObject]@{'CIDR'=$cidr;'NETMASK'=$network;'BINARY'=$binary}
}

function Get-CalendarArray
{
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false,Position = 0)][Int][ValidateRange(1950,2100)]$StartRange=(Get-Date).Year,
    [Parameter(Mandatory = $false,Position = 1)][Int][ValidateRange(1950,3000)]$EndRange=(Get-Date).AddYears(10).Year,
    [Parameter(Mandatory = $false,Position = 2)][Int][ValidateRange(1,100)]$RunspacePool=100,
    [Parameter(Mandatory = $false,Position = 3)][Switch]$FilterDate,
    [Parameter(Mandatory = $false,Position = 4)][Int][ValidateRange(0,31)]$DayNum=0,
    [Parameter(Mandatory = $false,Position = 5)][Int][ValidateRange(0,12)]$MonthNum=0,
    [Parameter(Mandatory = $false,Position = 6)][Int][ValidateRange(0,7)]$DayNameNum=7,
    [Parameter(Mandatory = $false,Position = 7)][Switch]$ShowProgress
)
<#requires PSAsync module#>
if ($ShowProgress)
{$ShowProgress=$true}
else
{$ShowProgress=$false}

$Years = @(); $StartRange..$EndRange | % {$Years += $_}

$MonthsArray = @()

foreach ($Year in $Years) {
    1..12 | % {
    $Months = New-Object -TypeName System.Object
    $Months | Add-Member -MemberType NoteProperty -Name Month -Value (((Get-Date -Month $_ -Day 1 -Hour 0 -Minute 0 -Second 0 -Year $Year).AddMonths(1).AddSeconds(-1)).Month)
    $Months | Add-Member -MemberType NoteProperty -Name Name -Value (Get-Date -Month $_ -Year $Year -Format "MMMM")
    $Months | Add-Member -MemberType NoteProperty -Name Days -Value (((Get-Date -Month $_ -Day 1 -Hour 0 -Minute 0 -Second 0 -Year $Year).AddMonths(1).AddSeconds(-1)).Day)
    $Months | Add-Member -MemberType NoteProperty -Name Year -Value $Year
    $MonthsArray += $Months
    }
}

$Days_Collection=@()

$ScriptBlock = { param($Month)
                    $SubObj=@()
                    $D_I_Y = ((Get-Date -Year $Month.Year -Month 12 -Day 1 -Hour 0 -Minute 0 -Second 0).AddMonths(1).AddSeconds(-1).DayOfYear)
                    1..$Month.Days | % {
                        $Day_Array=New-Object -TypeName System.Object
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Year -Value $Month.Year
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Days_In_Year -Value $D_I_Y
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Day_Of_Year_Num -Value (Get-Date -Year $Month.Year -Month $Month.Month -Day $_ -Hour 0 -Minute 0 -Second 0).DayOfYear
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Month_Name -Value $Month.Name
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Month_Num -Value $Month.Month
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Day_Num -Value $_
                        $Day_Array|Add-Member -MemberType NoteProperty -Name Day_Name -Value ([System.Globalization.DateTimeFormatInfo]::CurrentInfo.DayNames[((Get-Date -Year $Month.Year -Month $Month.Month -Day $_ -Hour 0 -Second 0).DayOfWeek.value__)])
                        $Day_Array|Add-Member -MemberType NoteProperty -Name DayNameNum -Value ((Get-Date -Year $Month.Year -Month $Month.Month -Day $_ -Hour 0 -Second 0).DayOfWeek.value__)
                        $SubObj+=$Day_Array  }
                        Write-Output $SubObj
                }
$Pool = Get-RunspacePool $RunspacePool
$AsyncPipelines=@()
foreach ($Month in $MonthsArray){

        $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $Month
    }
$null = Receive-AsyncStatus -Pipelines $AsyncPipelines
$Days_Collection+=Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress:$ShowProgress

    if ($FilterDate)
    {
        $i=0
        $FilterString = '{ $_'
        if ($DayNum -ne 0){$FilterString+='.Day_Num -eq $DayNum';$i=1}
        if ($MonthNum -ne 0){
            if ($i -ne 0){$FilterString+=' -and $_'}
                $FilterString+='.Month_Num -eq $MonthNum';$i=1
                }
        if ($DayNameNum -ne 7){
            if ($i -ne 0){$FilterString+=' -and $_'}
                $FilterString+='.DayNameNum -eq $DayNameNum';$i=1
                }
        $FilterString += ' }'
        Write-Verbose ("DayNum = $DayNum; MonthNum = $MonthNum; DayNameNum = $DayNameNum")
        Write-Verbose ('$Days_Collection | ? ' + $FilterString)
        iex ('$Days_Collection | ? ' + $FilterString)
    }
    else
    {$Days_Collection}
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

function Invoke-CheckConnection 
{
    [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()
}

function Get-ListeningPorts
{
#Get-ListeningPorts
    [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | % {
        [PSCustomObject]@{
            'Address'=$_.Address;
            'Port'=$_.Port;
            'IPv'=if 
                ($_.AddressFamily -eq 'InterNetwork'){4}
                else{6}
            }
        }
}

function Set-Hidden
{
#gci -Path c:\ -Filter '*.csv' -Force | Set-Hidden
param($Input)
BEGIN{}
PROCESS{
            [void](Set-ItemProperty -Path $_.FullName -Name Attributes -Value ('Hidden,Archive') -PassThru)
        }
END{}       
}

function Invoke-TestXMLFile 
{
[CmdletBinding()]
param (
[parameter(mandatory=$true)][ValidateNotNullorEmpty()][string]$File
)
$xml = New-Object System.Xml.XmlDocument
    try 
    {
        $xml.Load((Get-ChildItem -Path $File).FullName)
        $true
    }
    catch [System.Xml.XmlException] 
    {
        Write-Warning "$File : $($_.toString())"
        $false
    }
}

function Invoke-CreatePassword 
{
    param(
    $Number=1,
    $Length=10
    )
    $Rand = New-Object System.Random
    for($i=0;$i -lt $Number;$i++)
    {
            -join (1..$Length | ForEach { [char]$Rand.Next(33,127) })
    }
}

function Invoke-TurnOffMonitor
{
$signature = @"
    [DllImport("User32.DLL")]
    public static extern int SendMessage(IntPtr hWnd, UInt32 Msg, Int32 wParam, Int32 lParam);
"@
 
$type = Add-Type -MemberDefinition $signature -Name Win32 -Namespace SendMessage -PassThru
$type::SendMessage(0xFFFF,0x0112,0xF170,2)
}

function Get-WebClient 
{ 
[CmdLetBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('UTF8','Default','ASCII','Unicode')]
    [string]$Encoding='UTF8'
    )
#(Get-WebClient).DownloadString('http://www.yandex.ru')
    $wc = New-Object -TypeName Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::$Encoding
    $wc.UseDefaultCredentials = $true
    $wc.Proxy.Credentials = $wc.Credentials
    $wc
}

function Get-ExtendedWebClient
{ 
[CmdLetBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('UTF8','Default','ASCII','Unicode')]
    [string]$Encoding='UTF8',
    [Parameter(Mandatory=$false)]
    [Int]$Timeout=100000
    )
$Source = @"
	using System.Net;
 
	public class ExtendedWebClient : WebClient
	{
		public int Timeout;
 
		protected override WebRequest GetWebRequest(System.Uri address)
		{
			WebRequest request = base.GetWebRequest(address);
			if (request != null)
			{
				request.Timeout = Timeout;
			}
			return request;
		}
 
		public ExtendedWebClient()
		{
			Timeout = 100000; // the standard HTTP Request Timeout default
		}
	}
"@
Add-Type -TypeDefinition $Source -Language CSharp  
$wc = New-Object ExtendedWebClient
$wc.Timeout = $Timeout
$wc.Encoding = [System.Text.Encoding]::$Encoding
$wc.UseDefaultCredentials = $true
$wc.Proxy.Credentials = $wc.Credentials
$wc
}

function Get-DecryptedCpassword 
{
        [CmdletBinding()]
        Param (
            [string] $Cpassword 
        )

        try {
            $Mod = ($Cpassword.length % 4)
            
            switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
            $AesIV = New-Object Byte[]($AesObject.IV.Length) 
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor() 
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } 
        
        catch {Write-Error $Error[0]}
}

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
            [xml]$xml=(Invoke-WebRequest -Uri $target -ContentType 'text/xml' -UseDefaultCredentials -ProxyUseDefaultCredentials).Content
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

function Get-FunctionParams
{
#Get-FunctionParams Get-Process
param(
[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$FunctionName)
$result = @()
$set = @((help $FunctionName).parameters.parameter)
if ($set.Count -eq 0)
{
    Write-Host $('Function {0} has no parameters' -f $FunctionName)
    break
}
$set | % {
$item = $_
$object = New-Object -TypeName PSObject
$object | Add-Member -MemberType NoteProperty -Name Name -Value $item.name
$object | Add-Member -MemberType NoteProperty -Name aliases -Value $item.aliases
$object | Add-Member -MemberType NoteProperty -Name required -Value $item.required
$object | Add-Member -MemberType NoteProperty -Name type -Value $item.type.name
$object | Add-Member -MemberType NoteProperty -Name position -Value $item.position
$object | Add-Member -MemberType NoteProperty -Name defaultValue -Value $item.defaultValue
$object | Add-Member -MemberType NoteProperty -Name parameterSetName -Value $item.parameterSetName
$result += $object
}
Write-Output $result | Sort-Object position,Name | Format-Table -AutoSize -Wrap
}

function Add-PersonalDrive
{
    [System.Enum]::GetNames([System.Environment+SpecialFolder]) |
    ForEach-Object {
    $name = $_
    $target = [System.Environment]::GetFolderPath($_)
    New-PSDrive $name FileSystem $target -Scope Global
    }
}

function Convert-BmpToIcon 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateScript({
                    [System.IO.Path]::GetExtension($_) -eq '.bmp'
        })][string]$bitmapPath,
        [Parameter(Mandatory = $false)][string]$iconPath = "$env:temp\newicon.ico"
    )
    Add-Type -AssemblyName System.Drawing
    if (Test-Path $bitmapPath) 
    {
        $b = [System.Drawing.Bitmap]::FromFile($bitmapPath)
        $icon = [System.Drawing.Icon]::FromHandle($b.GetHicon())
        $file = New-Object -TypeName System.IO.FileStream -ArgumentList ($iconPath, 'OpenOrCreate')
        $icon.Save($file)
        $file.Close()
        $icon.Dispose()
        explorer.exe "/SELECT,$iconPath"
    }
    else 
    {
        Write-Warning -Message "$bitmapPath does not exist"
    }
}

function Invoke-ExtractIcon 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath = $env:USERPROFILE,
        [Parameter(Mandatory = $true)][string]$OutputPath = "$env:temp\icons"

    )
    Add-Type -AssemblyName System.Drawing

    [void](mkdir $OutputPath -ErrorAction 0)
    Get-ChildItem $SourcePath -Filter *.exe -ErrorAction 0 -Recurse |
    ForEach-Object -Process {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($_.FullName)
        Write-Progress 'Extracting Icon' -Status $baseName
        [System.Drawing.Icon]::ExtractAssociatedIcon($_.FullName).ToBitmap().Save("$OutputPath\$baseName.ico")
    }
    explorer.exe $OutputPath
}

function Get-CharCode
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateLength(1,999)][String]$String

    )
    [System.Collections.ArrayList]$CharSet = $String.ToCharArray()
    $Results = New-Object System.Collections.Specialized.OrderedDictionary
    [Int]$i=0
    do{
        $Current = [Char]$i
        if($CharSet.Contains($Current))
        {
            $Results.Add($Current,$i)
            do
            {
                $CharSet.Remove($Current)
            }
            while($CharSet.Contains($Current))
        }
        $i++
    }
    while($CharSet.Count -gt 0 -and $i -lt 65535)
    foreach ($Symbol in $String.ToCharArray())
    {
                New-Object -TypeName PSObject -Property @{
                    Char = $Symbol
                    Code = $Results[$Symbol]
                    Usage = '[System.Char]{0}' -f $Results[$Symbol]
                }
    }
}

function Set-AlternatingRows 
{
    <#
            .SYNOPSIS
            Simple function to alternate the row colors in an HTML table
            .DESCRIPTION
            This function accepts pipeline input from ConvertTo-HTML or any
            string with HTML in it.  It will then search for <tr> and replace 
            it with <tr class=(something)>.  With the combination of CSS it
            can set alternating colors on table rows.
		
            CSS requirements:
            .odd  { background-color:#ffffff; }
            .even { background-color:#dddddd; }
		
            Classnames can be anything and are configurable when executing the
            function.  Colors can, of course, be set to your preference.
		
            This function does not add CSS to your report, so you must provide
            the style sheet, typically part of the ConvertTo-HTML cmdlet using
            the -Head parameter.
            .PARAMETER Line
            String containing the HTML line, typically piped in through the
            pipeline.
            .PARAMETER CSSEvenClass
            Define which CSS class is your "even" row and color.
            .PARAMETER CSSOddClass
            Define which CSS class is your "odd" row and color.
            .EXAMPLE $Report | ConvertTo-HTML -Head $Header | Set-AlternateRows -CSSEvenClass even -CSSOddClass odd | Out-File HTMLReport.html
	
            $Header can be defined with a here-string as:
            $Header = @"
            <style>
            TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
            TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
            TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
            .odd  { background-color:#ffffff; }
            .even { background-color:#dddddd; }
            </style>
            "@
		
            This will produce a table with alternating white and grey rows.  Custom CSS
            is defined in the $Header string and included with the table thanks to the -Head
            parameter in ConvertTo-HTML.
            .NOTES
            Author:         Martin Pugh
            Twitter:        @thesurlyadm1n
            Spiceworks:     Martin9700
            Blog:           www.thesurlyadmin.com
		
            Changelog:
            1.1         Modified replace to include the <td> tag, as it was changing the class
            for the TH row as well.
            1.0         Initial function release
            .LINK
            http://community.spiceworks.com/scripts/show/1745-set-alternatingrows-function-modify-your-html-table-to-have-alternating-row-colors
            .LINK
            http://thesurlyadmin.com/2013/01/21/how-to-create-html-reports/
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Line,
       
        [Parameter(Mandatory)]
        [string]$CSSEvenClass,
       
        [Parameter(Mandatory)]
        [string]$CSSOddClass
    )
    Begin {
        $ClassName = $CSSEvenClass
    }
    Process {
        If ($Line.Contains('<tr><td>'))
        {
            $Line = $Line.Replace('<tr>',"<tr class=""$ClassName"">")
            If ($ClassName -eq $CSSEvenClass)
            {
                $ClassName = $CSSOddClass
            }
            Else
            {
                $ClassName = $CSSEvenClass
            }
        }
        Return $Line
    }
}

function Convert-AliasDefinition 
{
    #http://jdhitsolutions.com/blog/powershell-v2-0/1324/powershell-ise-alias-to-command/

    [cmdletBinding(DefaultParameterSetName = 'ToDefinition')]

    Param(
        [Parameter(Position = 0,Mandatory = $true,HelpMessage = 'Enter a string to convert')]
        [string]$Text,
        [Parameter(ParameterSetName = 'ToAlias')]
        [switch]$ToAlias,
        [Parameter(ParameterSetName = 'ToDefinition')]
        [switch]$ToDefinition
    )

    #make sure we are using the ISE
    if ($host.name -match 'ISE')
    {
        Try
        {
            #get alias if it exists otherwise throw an exception that
            #will be caught
            if ($ToAlias)
            {
                #get alias by definition and convert to name
                $alias = Get-Alias -Definition $Text -ErrorAction Stop
                #there might be multiples so use the first one found
                if ($alias -is [array])
                {
                    $replace = $alias[0].name
                }
                else
                {
                    $replace = $alias.name
                }
            }
            else
            {
                #get alias by name and convert to definition

                #if the text is ?, this is a special character so
                #we'll just assume it is Where-Object
                if ($Text -eq '?')
                {
                    $replace = 'Where-Object'
                }
                else
                {
                    $alias = Get-Alias -Name $Text -ErrorAction Stop
                    $replace = $alias.definition
                }
            } #Else ToDefinition
        } #close Try

        Catch
        {
            Write-Host -Object "Nothing for for $Text" -ForegroundColor Cyan
        }

        Finally
        {
            #make changes if an alias was found
            If ($replace)
            {
                #Insert the replacment
                $psise.currentfile.editor.insertText($replace)
            }
        }
    } #if ISE
    else
    {
        Write-Warning -Message 'You must be using the PowerShell ISE'
    }
}

function Start-IisExpress 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0)][string]$SiteName,
        [Parameter(Mandatory = $false,Position = 1)][ValidateSet('true','false')][string]$ShowTrayIcon = 'true',
        [Parameter(Mandatory = $false,Position = 2)][string]$JobName = 'IISExpressJob'
    )
    $IIS = "$env:ProgramFiles\IIS Express\iisexpress.exe"
    $Arguments = $IIS, $SiteName, $ShowTrayIcon
    if(Test-Path -Path "$env:ProgramFiles\IIS Express\iisexpress.exe")
    {
        [void](Start-Job -Name $JobName -ScriptBlock {
                Invoke-Expression "& '$($args[0])' /site:$($args[1]) /systray:$($args[2])"
        } -ArgumentList $Arguments)
    }
    else
    {
        Write-Warning -Message "$env:ProgramFiles\IIS Express\iisexpress.exe not found!"
    }
}

function Stop-IisExpress 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][string]$JobName = 'IISExpressJob'
    )
    Stop-Job -Name $JobName
    Remove-Job -Name $JobName
}

function Set-Credentials 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,Position = 0)][ValidateNotNull()][String]$UserName,
        [Parameter(Mandatory = $false,ValueFromPipeline = $true,Position = 1)][ValidateNotNull()][String]$UserPassword
    )
    if (-not$UserPassword)
    {
        $Password = Read-Host -Prompt "Specify password for $UserName" -AsSecureString
    }
    else
    {
        $Password = (ConvertTo-SecureString -String $UserPassword -AsPlainText -Force)
    }
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($UserName, $Password)
    Write-Output -InputObject $Credentials
}

function Get-EnumValues 
{
    #Get-EnumValues -Enumeration "System.Diagnostics.Eventing.Reader.StandardEventLevel"
    #Get-EnumValues -Enumeration ([System.Management.Automation.ActionPreference])
    Param([string]$Enumeration)
    $EnumerationValues = @{}
    [enum]::getvalues([type]$Enumeration) | ForEach-Object -Process {
        $EnumerationValues.add($_, $_.value__)
    }
    Write-Output -InputObject $EnumerationValues
} 

function Out-DataGridView 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
            [ValidateNotNull()]$Data,
        [Parameter(Mandatory = $false)][String]$Title,
        
        [Parameter(Mandatory = $false)]
            [ValidateSet('None','ColumnHeader','AllCellsExceptHeader','AllCells','DisplayedCellsExceptHeader','DisplayedCells','Fill')]
                [String]$AutoSizeColumnsMode='Fill',
        [Parameter(Mandatory = $false)]
            [ValidateSet('Regular','Bold','Italic','Underline','Strikeout')]
                [string]$FontStyle='Regular',
        [Parameter(Mandatory = $false)][int]$FontSize=10,
        [Parameter(Mandatory = $false)][Switch]$Maximized
)
    [System.Windows.Forms.Application]::EnableVisualStyles()
    if($input)
    {
        $Data = $input
    }
    $Form = New-Object -TypeName 'System.Windows.Forms.Form'
    $DGV = New-Object -TypeName 'System.Windows.Forms.DataGridView'
    $OnLoadFormEvent = { 
        $DGV.SuspendLayout()
        if ($Data -is [System.ComponentModel.IListSource]`
        -or $Data -is [System.ComponentModel.IBindingList] -or $Data -is [System.ComponentModel.IBindingListView] )
        {
            $DGV.DataSource = $Data
        }
        else
        {	
            $array = New-Object -TypeName System.Collections.ArrayList
            if ($Data -is [System.Collections.IList])
            {
                $array.AddRange($Data)
            }
            else
            {
                $array.Add($Data)
            }
            $DGV.DataSource = $array
        }
        'RowError', 'RowState', 'Table', 'HasErrors' |
        ForEach-Object -Process {
            if($DGV.Columns.Contains($_))
            {
                $DGV.Columns.Remove($_)
            }
        }
        $DGV.ResumeLayout()
    }
    $DGV_DataError = [System.Windows.Forms.DataGridViewDataErrorEventHandler]{
        Write-Verbose -Message "Error accured`n$_"
    }
    if($Maximized)
    {
        $Form.WindowState = 'Maximized'
    }
    if($Title)
    {
        $Form.Text = $Title
    }
    $Form.SuspendLayout()
    $Form.Controls.Add($DGV)
    $Form.ClientSize = '500, 500'
    $Form.FormBorderStyle = 'SizableToolWindow'
    $Form.StartPosition = 'CenterScreen'
    $Form.add_Load($OnLoadFormEvent)
    
    $DGV.AlternatingRowsDefaultCellStyle.BackColor = 'Gainsboro'
    $DGV.AlternatingRowsDefaultCellStyle.Font = New-Object -TypeName System.Drawing.Font('Tahoma', $FontSize, [System.Drawing.FontStyle]::$FontStyle)
    $DGV.DefaultCellStyle.BackColor = 'White'
    $DGV.DefaultCellStyle.Font = New-Object -TypeName System.Drawing.Font('Tahoma', $FontSize, [System.Drawing.FontStyle]::$FontStyle)
    $DGV.ColumnHeadersDefaultCellStyle.Font = New-Object -TypeName System.Drawing.Font('Tahoma', ($FontSize+2), [System.Drawing.FontStyle]::Bold)

    $DGV.AllowUserToAddRows = $false
    $DGV.AllowUserToDeleteRows = $false
    $DGV.AllowUserToOrderColumns = $true
    $DGV.AllowUserToResizeColumns = $false
    $DGV.AllowUserToResizeRows = $false
    $DGV.AutoSizeColumnsMode = $AutoSizeColumnsMode
    $DGV.AutoSizeRowsMode = 'AllCells'
    $DGV.BorderStyle = 'Fixed3D'
    $DGV.ColumnHeadersHeightSizeMode = 'AutoSize'
    $DGV.Dock = 'Fill'
    $DGV.Location = '0, 0'
    $DGV.ReadOnly = $true
    $DGV.RowHeadersWidth = 25
    $DGV.RowHeadersWidthSizeMode = 'DisableResizing'
    $DGV.ShowCellErrors = $false
    $DGV.ShowRowErrors = $false
    $DGV.Size = '500, 500'
    $DGV.TabIndex = 0
    $DGV.add_DataError($DGV_DataError)
    $Form.ResumeLayout($false)
    return [void]($Form.ShowDialog())
}

function Convert-ColorToExcel 
{
    [CmdletBinding()]
    param([System.Drawing.Color]$Color)
    $Color.R + ($Color.G * 256) + ($Color.B * 256*256)
}

function Convert-ToEncoding 
{
    <#
            PS C:\> $Windows1251ToUTF8 = Convert-ToEncoding -String 'привет' -FromCodePage windows-1251 -ToCodePage utf-8
            $Windows1251ToUTF8
            РїСЂРёРІРµС'

            PS C:\> $UTF8ToWindows1251 = Convert-ToEncoding -String $Windows1251ToUTF8 -FromCodePage utf-8 -ToCodePage windows-1251
            $UTF8ToWindows1251
            привет
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][String]$String,
        [Parameter(Mandatory = $true,Position = 1)][ValidateSet(
                'IBM037','IBM437','IBM500','ASMO-708','DOS-720','ibm737','ibm775','ibm850','ibm852','IBM855',
                'ibm857','IBM00858','IBM860','ibm861','DOS-862','IBM863','IBM864','IBM865','cp866','ibm869',
                'IBM870','windows-874','cp875','shift_jis','gb2312','ks_c_5601-1987','big5','IBM1026','IBM01047',
                'IBM01140','IBM01141','IBM01142','IBM01143','IBM01144','IBM01145','IBM01146','IBM01147','IBM01148',
                'IBM01149','utf-16','utf-16BE','windows-1250','windows-1251','Windows-1252','windows-1253',
                'windows-1254','windows-1255','windows-1256','windows-1257','windows-1258','Johab','macintosh',
                'x-mac-japanese','x-mac-chinesetrad','x-mac-korean','x-mac-arabic','x-mac-hebrew','x-mac-greek',
                'x-mac-cyrillic','x-mac-chinesesimp','x-mac-romanian','x-mac-ukrainian','x-mac-thai','x-mac-ce',
                'x-mac-icelandic','x-mac-turkish','x-mac-croatian','utf-32','utf-32BE','x-Chinese-CNS','x-cp20001',
                'x-Chinese-Eten','x-cp20003','x-cp20004','x-cp20005','x-IA5','x-IA5-German','x-IA5-Swedish',
                'x-IA5-Norwegian','us-ascii','x-cp20261','x-cp20269','IBM273','IBM277','IBM278','IBM280',
                'IBM284','IBM285','IBM290','IBM297','IBM420','IBM423','IBM424','x-EBCDIC-KoreanExtended',
                'IBM-Thai','koi8-r','IBM871','IBM880','IBM905','IBM00924','EUC-JP','x-cp20936','x-cp20949',
                'cp1025','koi8-u','iso-8859-1','iso-8859-2','iso-8859-3','iso-8859-4','iso-8859-5','iso-8859-6',
                'iso-8859-7','iso-8859-8','iso-8859-9','iso-8859-13','iso-8859-15','x-Europa','iso-8859-8-i',
                'iso-2022-jp','csISO2022JP','iso-2022-jp','iso-2022-kr','x-cp50227','euc-jp','EUC-CN','euc-kr',
                'hz-gb-2312','GB18030','x-iscii-de','x-iscii-be','x-iscii-ta','x-iscii-te','x-iscii-as',
        'x-iscii-or','x-iscii-ka','x-iscii-ma','x-iscii-gu','x-iscii-pa','utf-7','utf-8')][string]$FromCodePage,
        [Parameter(Mandatory = $true,Position = 2)][ValidateSet(
                'IBM037','IBM437','IBM500','ASMO-708','DOS-720','ibm737','ibm775','ibm850','ibm852','IBM855',
                'ibm857','IBM00858','IBM860','ibm861','DOS-862','IBM863','IBM864','IBM865','cp866','ibm869',
                'IBM870','windows-874','cp875','shift_jis','gb2312','ks_c_5601-1987','big5','IBM1026','IBM01047',
                'IBM01140','IBM01141','IBM01142','IBM01143','IBM01144','IBM01145','IBM01146','IBM01147','IBM01148',
                'IBM01149','utf-16','utf-16BE','windows-1250','windows-1251','Windows-1252','windows-1253',
                'windows-1254','windows-1255','windows-1256','windows-1257','windows-1258','Johab','macintosh',
                'x-mac-japanese','x-mac-chinesetrad','x-mac-korean','x-mac-arabic','x-mac-hebrew','x-mac-greek',
                'x-mac-cyrillic','x-mac-chinesesimp','x-mac-romanian','x-mac-ukrainian','x-mac-thai','x-mac-ce',
                'x-mac-icelandic','x-mac-turkish','x-mac-croatian','utf-32','utf-32BE','x-Chinese-CNS','x-cp20001',
                'x-Chinese-Eten','x-cp20003','x-cp20004','x-cp20005','x-IA5','x-IA5-German','x-IA5-Swedish',
                'x-IA5-Norwegian','us-ascii','x-cp20261','x-cp20269','IBM273','IBM277','IBM278','IBM280',
                'IBM284','IBM285','IBM290','IBM297','IBM420','IBM423','IBM424','x-EBCDIC-KoreanExtended',
                'IBM-Thai','koi8-r','IBM871','IBM880','IBM905','IBM00924','EUC-JP','x-cp20936','x-cp20949',
                'cp1025','koi8-u','iso-8859-1','iso-8859-2','iso-8859-3','iso-8859-4','iso-8859-5','iso-8859-6',
                'iso-8859-7','iso-8859-8','iso-8859-9','iso-8859-13','iso-8859-15','x-Europa','iso-8859-8-i',
                'iso-2022-jp','csISO2022JP','iso-2022-jp','iso-2022-kr','x-cp50227','euc-jp','EUC-CN','euc-kr',
                'hz-gb-2312','GB18030','x-iscii-de','x-iscii-be','x-iscii-ta','x-iscii-te','x-iscii-as',
        'x-iscii-or','x-iscii-ka','x-iscii-ma','x-iscii-gu','x-iscii-pa','utf-7','utf-8')][string]$ToCodePage
    )
    Begin{
        $EncFrom = [System.Text.Encoding]::GetEncoding($FromCodePage)
        $EncTo = [System.Text.Encoding]::GetEncoding($ToCodePage)
    }
    Process{
        if($input)
        {
            $String = $input
        }
        [Byte[]]$Bytes = $EncTo.GetBytes($String)
        [Byte[]]$Bytes = [System.Text.Encoding]::Convert($EncFrom, $EncTo, $Bytes)
        $EncTo.GetString($Bytes)
    }
}

function Get-StringEncoding
{
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][String]$String)

    $FullList = [System.Text.Encoding]::GetEncodings()
    foreach ($Item in $FullList)
    {
        for ($i=0;$i -lt $FullList.Count;$i++){
            $EncFrom = [System.Text.Encoding]::GetEncoding($Item.Name)
            $EncTo = [System.Text.Encoding]::GetEncoding($FullList[$i].Name)
            [Byte[]]$Bytes = $EncTo.GetBytes($String)
            [Byte[]]$Bytes = [System.Text.Encoding]::Convert($EncFrom, $EncTo, $Bytes)
            New-Object PSObject -Property @{
                'FromCode'= $Item.Name
                'FromName' = $Item.DisplayName
                'ToCode'= $FullList[$i].Name
                'ToName' = $FullList[$i].DisplayName
                'Result'= $EncTo.GetString($Bytes)                
            } | Select FromCode, FromName, ToCode, ToName, Result
        }
    }
}

function Get-BroadCastIpAddress 
{
    [wmi[]]$IpLocal = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
    Where-Object -FilterScript {
        $_.IPAddress
    } |
    Select-Object -First 1
    [UInt32]$IpBroadCast = [UInt32]([IPAddress]::Parse(@($IpLocal.IPAddress)[0]).Address) `
    -band [UInt32]([IPAddress]::Parse(@($IpLocal.IPSubnet)[0]).Address)
    Write-Output -InputObject $([IPAddress]($IpBroadCast -bor -bnot [UInt32]([IPAddress]::Parse(@($IpLocal.IPSubnet)[0]).Address)))
}

function Invoke-TCPServer
{
[CmdletBinding()]
[OutputType([String[]])]
    Param(
    [Parameter(Mandatory = $true,Position = 0)][Int][ValidateRange(2,65535)]$Port,
    [Parameter(Mandatory = $false,Position = 1)][System.Net.IPAddress]$ListenInterface = [System.Net.IPAddress]::Any, #[System.Net.IPAddress]'127.0.0.1'
    [Parameter(Mandatory = $true,Position = 2)][String]$User,
    [Parameter(Mandatory = $true,Position = 3)][String]$Password,
    [Parameter(Mandatory = $false,Position = 4)][Switch]$InvokeExpression
)
    $DateTimeFormat = 'dd.MM.yyyy hh:mm:ss'
    
    $Credentials = ':U:{0}:P:{1}:' -f $User,$Password
    $StopCMD = ':STOPNOW:'
    $StatusCMD = ':STATUS:'
    $Counter = 0
    Write-Verbose -Message $('[{0}][{1}:{2}] Server started' -f $(Get-Date -Format $DateTimeFormat),$ListenInterface.IPAddressToString,$Port)
    if ($InvokeExpression)
    {
        Write-Verbose -Message $('[{0}][{1}:{2}] InvokeExpression mode is enabled' -f $(Get-Date -Format $DateTimeFormat),$ListenInterface.IPAddressToString,$Port)
    }
    $EndPoint = New-Object System.Net.IPEndPoint ($ListenInterface, $Port)
    $Listener = New-Object System.Net.Sockets.TcpListener $EndPoint
    try
    {
        Write-Verbose -Message $('[{0}][{1}:{2}] LocalEndpoint is set to: "{3}"' -f $(Get-Date -Format $DateTimeFormat),$ListenInterface.IPAddressToString,$Port,$($Listener.LocalEndpoint))
        Write-Verbose -Message $('[{0}][{1}:{2}] User is set to: "{3}"' -f $(Get-Date -Format $DateTimeFormat),$ListenInterface.IPAddressToString,$Port,$User)
        Write-Verbose -Message $('[{0}][{1}:{2}] Password is set to: "{3}"' -f $(Get-Date -Format $DateTimeFormat),$ListenInterface.IPAddressToString,$Port,$Password)
        $Listener.Start()
        $StartTime = Get-Date -Format $DateTimeFormat
        Write-Verbose -Message $('[{0}][{1}:{2}] Server started' -f $StartTime,$ListenInterface.IPAddressToString,$Port)
    }
    catch
    {
        Write-Verbose -Message $('[{0}][{1}:{2}] Failed to start server' -f $StartTime,$ListenInterface.IPAddressToString,$Port)
        Write-Warning -Message $('[{0}][{1}:{2}] Failed to start server' -f $StartTime,$ListenInterface.IPAddressToString,$Port)
        throw $Error[0].Exception.Message
        break
    }
    do {
        $Client = $Listener.AcceptTcpClient() # will block here until connection
        $Stream = $Client.GetStream()
        $Reader = New-Object System.IO.StreamReader $Stream
        do {
            $Message = $Reader.ReadLine() #':U:usr123:P:P@$$:MSG:GET-DATE'
            [Array]$MessageCheck = $Message -split 'MSG:'
            if ($MessageCheck[0] -and $MessageCheck[1] -and $MessageCheck[0] -ceq $Credentials)
            {
                $Line = $MessageCheck[1]
                if ($Line -ceq $StopCMD)
                {
                    Write-Verbose -Message $('[{0}][{1}] Stop server requested' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Stopping server' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                }
                elseif ($Line -ceq $StatusCMD)
                {
                    Write-Verbose -Message $('[{0}][{1}] Status server request' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Status server request' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Server is running since: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$StartTime)
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] LocalEndpoint is set to: "{2}"' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$($Listener.LocalEndpoint))
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Allowed user name: "{2}"' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$User)
                    Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Allowed user password: "{2}"' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$Password)
                    if ($InvokeExpression)
                    {
                        Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Server is running in InvokeExpression mode' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                        Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Number of invoked commands: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$Counter)
                    }
                    else
                    {
                        Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Server is running in receiveing messages mode' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint))
                        Write-Host -BackgroundColor Black -ForegroundColor Green $('[{0}][{1}] Number of received messages: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$Counter)
                    }
                }
                else
                {
                    $Counter++
                    if ($InvokeExpression)
                    {
                        Write-Verbose -Message $('[{0}][{1}][SUCCESS] Invoked command: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$Line)
                        try 
                            {
                                $Code = [ScriptBlock]::Create($Line)
                                $PS = [PowerShell]::Create()
                                [void]$PS.AddScript($Code)
                                [void]$ps.BeginInvoke()
                            }
                        catch 
                            {
                                Write-Warning $Error[0].Exception.Message
                            }
                    }
                    else
                    {
                        Write-Verbose -Message $('[{0}][{1}][SUCCESS] Received message: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$Line)
                        Write-Output $Line
                    }

                }
            }
            else
            {
                if ($MessageCheck[0] -and $MessageCheck[1])
                {
                    if ($MessageCheck[0] -cne $Credentials)
                    {
                        Write-Verbose -Message $('[{0}][{1}][ERROR] Wrong credentials provided: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$MessageCheck[0])
                        Write-Verbose -Message $('[{0}][{1}][ERROR] Message: {2}' -f $(Get-Date -Format $DateTimeFormat),$($Listener.LocalEndpoint),$MessageCheck[1])
                    }
                }
            }

        } while ($Message -and $Line -cne $StopCMD)
        $Reader.Dispose()
        $Stream.Dispose()
        $Client.Dispose() 
    } while ($Line -cne $StopCMD)
    $Listener.Stop()
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

function Invoke-TCPRequest 
{
[CmdletBinding()]
[OutputType([String[]])]
param(
    [Parameter(Mandatory = $true,Position = 0)][Int][ValidateRange(2,65535)]$Port,
    [Parameter(Mandatory = $false,Position = 1)][String]$Message='Hello World!',
    [Parameter(Mandatory = $false,Position = 2)][String]$Hostname='localhost',
    [Parameter(Mandatory = $false, Position = 3)][Switch]$TCPServerStopNow
)
    if ($TCPServerStopNow)
    {$Message = 'TCPServerStopNow'}

    try {
            $Client = New-Object System.Net.Sockets.TcpClient $Hostname, $Port
            $Stream = $Client.GetStream()
        }
    catch {Write-Warning $Error[0].Exception.Message}
    try {
            $Writer = New-Object System.IO.StreamWriter $Stream
            $Writer.Write($Message)
        }
    catch {Write-Warning $Error[0].Exception.Message}
    $Writer.Dispose()
    $Stream.Dispose()
    $Client.Dispose()
}

function Invoke-UDPRequest 
{
    #Invoke-UDPRequest -String 'hello world' -Port 12345 -IPEndPoint $(Get-BroadCastIpAddress) -CodePage UTF8 -Verbose
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0)][ValidateNotNullOrEmpty()][String]$String,
        [Parameter(Mandatory = $true,Position = 1)][ValidateRange(2,65535)][Int]$Port,
        [Parameter(Mandatory = $false,Position = 2)][IPAddress]$IPEndPoint = [IPAddress]::Loopback,
        [Parameter(Mandatory = $false,Position = 3)][ValidateSet('ASCII','BigEndianUnicode','Default','Unicode','UTF32','UTF7','UTF8')][String]$CodePage = 'UTF8'
    )
    $EndPoint = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ($IPEndPoint, $Port)
    Write-Verbose -Message "Endpoint is set to $($IPEndPoint.IPAddressToString):$Port"
    $UdpClient = New-Object -TypeName System.Net.Sockets.UdpClient
    $b = [Text.Encoding]::$CodePage.GetBytes($String)
    Write-Verbose -Message "Sending string $String"
    $BytesSent = $UdpClient.Send($b,$b.length,$EndPoint)
    $UdpClient.Close()
    $UdpClient.Dispose()
}

function Invoke-UDPServer 
{
    #Invoke-UDPServer -Port 12345 -ListenSeconds 30 -CodePage UTF8 -Verbose
    [CmdletBinding()]
    [OutputType([String[]])]
    Param(
        [Parameter(Mandatory = $true,Position = 0)][Int][ValidateRange(2,65535)]$Port,
        [Parameter(Mandatory = $false,Position = 1)][Int]$ListenSeconds = 10,
        [Parameter(Mandatory = $false,Position = 2)][IPAddress]$IPEndPoint = [IPAddress]::Any,
        [Parameter(Mandatory = $false,Position = 3)][ValidateSet('ASCII','BigEndianUnicode','Default','Unicode','UTF32','UTF7','UTF8')][String]$CodePage = 'UTF8'
    )
    BEGIN 
    {
        $EndPoint = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ($IPEndPoint, $Port)
        Write-Verbose -Message "Endpoint is set to $($IPEndPoint.IPAddressToString):$Port"
        $UdpClient = New-Object -TypeName System.Net.Sockets.UdpClient -ArgumentList $Port
        $i = 0
        Write-Verbose -Message "Listen seconds timeout is set to $ListenSeconds(Sec)"
    } 
    PROCESS
    {
        do
        {
            if ($UdpClient.Available -ne 0 -and $UdpClient.Available -ne $null)
            {
                Write-Verbose -Message "Received data (Timeout(Sec) was $([System.Math]::Round(($i/20),2))/$($ListenSeconds))"
                $i = 0
                Write-Verbose -Message "Timeout(Sec) reset ($($i/20)/$($ListenSeconds))"
                $Content = $UdpClient.Receive([ref]$EndPoint)
                [Text.Encoding]::$CodePage.GetString($Content)
            }
            Start-Sleep -Milliseconds 50
            $i++
        }
        until ($UdpClient.Available -eq 0 -and $i -eq ($ListenSeconds*20))
        if($i -eq ($ListenSeconds*20))
        {
            Write-Verbose -Message "ListenSeconds $ListenSeconds reached"
        }
    }
    END
    {
        $UdpClient.Close()
        $UdpClient.Dispose()
    }
}

function Convert-ImageToBase64 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    if(Test-Path -Path $_ -PathType Leaf)
                    {
                        (Get-ItemProperty -Path $_).Extension.Remove(0,1) -match '^(BMP|GIF|JPEG|JPG|PNG|TIFF|WMF)$'
                    }
        })]
        [Alias('FullName')][String]$Path
    )
    $Extension = (Get-ItemProperty -Path $Path).Extension.Remove(0,1)
    if($Extension -eq 'JPG')
    {
        $Extension = 'JPEG'
    }
    $Image = [System.Drawing.Image]::FromFile($Path)
    $MemoryStream = New-Object -TypeName IO.MemoryStream
    $Image.Save($MemoryStream, $Extension)
    $ImageBytes = $MemoryStream.ToArray()
    Write-Output -InputObject $([Convert]::ToBase64String($ImageBytes))
}

function Convert-Base64toImage 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)][String]$Base64String,
        [Parameter(Mandatory = $true,Position = 1,ValueFromPipeline = $true)]
        [ValidateScript(
                {
                    if(Test-Path -Path $_ -PathType Leaf -IsValid)
                    {
                        if(-not(Test-Path -Path $_))
                        {
                            ([System.IO.Path]::GetExtension($_).Remove(0,1) -match '^(BMP|GIF|JPEG|JPG|PNG|TIFF|WMF)$')
                        }
                    }
        })]$FilePath
    )
    $ImageBytes = [Convert]::FromBase64String($Base64String)
    $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList ($ImageBytes, 0, $ImageBytes.Length)
    $MemoryStream.Write($ImageBytes, 0, $ImageBytes.Length)
    $Image = [System.Drawing.Image]::FromStream($MemoryStream, $true)
    $Image.Save($FilePath)
}

function Invoke-ReplaceInvalidCharacters 
{
    #Invoke-ReplaceInvalidCharacters $(get-date).ToString()
    #Invoke-ReplaceInvalidCharacters -InputString 'my?string' -ReplacementChar '.'
    Param(
        [Parameter(Mandatory = $true,Position = 0)][string]$InputString,
        [Parameter(Mandatory = $false,Position = 1)][ValidateScript({
                    $_ -notin [System.IO.Path]::GetInvalidFileNameChars(), [System.IO.Path]::InvalidPathChars
    })][string]$ReplacementChar = '-')
    $InputString -replace "[$([System.IO.Path]::GetInvalidFileNameChars())]|[$([System.IO.Path]::InvalidPathChars)]", $ReplacementChar
}

function Invoke-SendModules 
{
    [CmdletBinding()]
    Param([String[]]$ModuleName)
    BEGIN{$ModulesArray = @()}
    PROCESS{
        foreach ($Module in $ModuleName)
        {
            $ModulePath = Get-ChildItem -Path $env:PSModulePath.Split(';') |
            Where-Object -FilterScript {
                $_.Name -eq $Module
            } |
            Select-Object -ExpandProperty FullName
            if (Test-Path $ModulePath)
            {
                try
                {
                    Import-ZipArchive -Source $ModulePath -DestinationFolder $env:temp -CompressionLevel Optimal -Overwrite -Verbose
                    $ModulesArray += "$(Join-Path -Path $env:temp -ChildPath $Module).zip"
                }
                catch
                {
                    Write-Warning -Message "Ошибка архивации файла $ModulePath`n$_"
                    break
                }  
            }
            else
            {
                Write-Warning -Message "Модуль $Module не найден"
            }
        }
    }
    END{
        try
        {
            Send-MailMessage @EmailSettingsYandex -BodyAsHtml -Body "Sending modules:<br><br/><b>$($ModuleName -join '<br>')<b/><br><br/>$(Get-Date)" -Attachments $ModulesArray -Subject "Modules package ($($ModulesArray.Count))"
            Write-Verbose "Успех отправки email для получателей $($EmailSettingsYandex.To -join ',')"
        }
        catch
        {
            Write-Warning "Ошибка отрпавки email для получателей $($EmailSettingsYandex.To -join ',')`n$_)"
        }
        foreach ($ArchiveToRemove in $ModulesArray)
        {
            try
            {
                Remove-Item -Path $ArchiveToRemove -Force -Confirm:$false
                Write-Verbose "Файл $ArchiveToRemove успешно удален"
            }
            catch
            {
                Write-Warning "Ошибка удаления файла $ArchiveToRemove`n$_"
            }
        }
    }
}

function Convert-ImageToExcel 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,HelpMessage = 'Image file path')][ValidateScript({
                    Test-Path $_
        })][String]$file,
        [Parameter(Mandatory = $false,Position = 1)][ValidateScript({
                    Test-Path $_
        })][String]$OutputFolder = $env:SystemDrive,
        [Parameter(Mandatory = $false,Position = 2)][String]$FileMask = $(Get-Date -UFormat '%d-%m-%Y-%H-%M-%S'),
        [Parameter(Mandatory = $false,Position = 3)][ValidateSet('XLS','XLSX')][String]$Format = 'XLSX',
        [Parameter(Mandatory = $false)][Switch]$Visible,
    [Parameter(Mandatory = $false)][Switch]$InvokeOnCompletion)
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    $Image = New-Object System.Drawing.Bitmap -ArgumentList $file
    try
    {
        $o = New-Object -ComObject Excel.Application
    }
    catch
    {
        Write-Warning "Cannot initialize Excel object`n$_"
        break
    }
    $i = 0
    $wait = $null
    $o.DisplayAlerts = $false
    $wb = $o.Workbooks.Add()
    $sh = $wb.ActiveSheet
    $sh.Cells.ColumnWidth = 0.25
    $sh.Cells.RowHeight = 2.5
    $total = $Image.Width * $Image.Height
    Write-Verbose "`nInput Image:`nWidth:$($Image.Width)`nHeight:$($Image.Height)`nPixels:$total"
    $s = [datetime]::Now
    if($Visible)
    {
        $o.Visible = $true
    }
    try
    {
        foreach($x in 0..($Image.Width-1))
        {
            foreach($y in 0..($Image.Height-1))
            {
                $elapsed = $(New-TimeSpan $s -End ([datetime]::Now))               
                $percent = $([System.Math]::Round([Decimal](($i/$total)*100),2))
                $progress = "Progress:`t`t`t$('{0:N2}' -f $percent)`t%`t`t`tElapsed:`t`t`t~`t$($elapsed.ToString() -replace '[.].*')"
                if($percent -gt 1)
                {
                    if($wait -eq $null)
                    {
                        $waittotal = New-TimeSpan -Seconds $([int]$elapsed.TotalSeconds*99)
                    }
                    $wait = $waittotal.Add(-$elapsed.Ticks)
                    $progress += "`t`t`tTime left:`t`t`t~`t$($wait.ToString() -replace '[.].*')"
                }
                Write-Progress $progress -PercentComplete  ((($x * $Image.Height + $y) / $total ) * 100)
                $sh.Cells.Item($y+1, $x+1).Interior.Color = Convert-ColorToExcel -Color ($Image.GetPixel($x, $y))
                #$sh.Cells.Range($sh.Cells.Item(1,1),$sh.Cells.Item(30,30)).Interior.Color = Convert-ColorToExcel -Color ($image.GetPixel($x, $y))
                $i++
            }
        }
    }
    catch
    {
        Write-Warning "Cannot access excel object`n$_"
        $o.Quit()
        break
    }
    try
    {
        if(-not($Visible))
        {
            $Item = "$(Join-Path $OutputFolder -ChildPath $FileMask).$Format"
            $o.ActiveWorkbook.SaveAs($Item)
            if ($InvokeOnCompletion)
            {
                Invoke-Item $Item -ErrorAction Stop
            }
        }
        $o.Quit()
        Write-Verbose "Generating completed. File saved to $Item"
    }
    catch
    {
        Write-Warning "Error saving excel file`n$_`nOpening excel object result instead"
        $o.Visible = $true
        break
    }
}

function Get-AssetInfo {

[CmdletBinding()]
    <#
.SYNOPSIS
   Get inventory data for specified computer system.
.DESCRIPTION
   Get inventory data for provided host using wmi.
   Data proccessing use multithreading and support using timeouts in case of wmi problems.
   Target computer system must be reacheble using ICMP Echo.
   Provide ComputerName specified by user and HostName used by OS. Also provide OS version, CPU and memory info.
.PARAMETER ComputerName
   Specifies the target computer for data query.
.PARAMETER ThrottleLimit
   Specifies the maximum number of systems to inventory simultaneously 
.PARAMETER Timeout
   Specifies the maximum time in second command can run in background before terminating this thread.
.PARAMETER ShowProgress
   Show progress bar information
.EXAMPLE
   PS > Get-AssetInfo -ComputerName test1
 
   ComputerName : hp-test1
   OSCaption    : Microsoft Windows 8 Enterprise
   Memory       : 5,93 GB
   Cores        : 2
   Sockets      : 1
 
   Description
   -----------
   Query information ablout computer test1
.EXAMPLE
   PS > Get-AssetInfo -ComputerName test1 -Credential (get-credential) | fromat-list * -force
 
   ComputerName   : hp-test1
   OSCaption      : Microsoft Windows 8 Enterprise
   OSVersion      : 6.2.9200
   Cores          : 2
   OSServicePack  : 0
   Memory         : 5,93 GB
   Sockets        : 1
   PSComputerName : test1
   Description
   -----------
   Query information ablout computer test1 using alternate credentials
.EXAMPLE
   PS > get-content C:\complist.txt | Get-AssetInfo -ThrottleLimit 100 -Timeout 60 -ShowProgress
 
   Description
   -----------
   Query information about computers in file C:\complist.txt using 100 thread at time with 60 sec timeout and showing progressbar
.EXAMPLE
   PS > $a = Get-AssetInfo
   PS > $a | Select Memory,Chassis
   
   Description
   -----------
   Query information about the  local computer, store in $a and then show output for the Memory and Chassis property groups

.NOTES
   Originally posted at: http://learn-powershell.net/2013/05/08/scripting-games-2013-event-2-favorite-and-not-so-favorite/
   Extended and further hacked by: Zachary Loeber
   Site: http://www.the-little-things.net/
   Requires: Powershell 2.0
   Info: WMI prefered over CIM as there no speed advantage using cimsessions in multitheating against old systems.
   The following are the default property groups you can send to output:
    - Default
    - System
    - OS
    - Processor
    - Chassis
    - Memory
    - MemoryArray
    - Network
#>
    Param
    (
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DNSHostName','PSComputerName')]
        [string[]]
        $ComputerName=$env:COMPUTERNAME,
 
        [Parameter(Position=1)]
        [ValidateRange(1,65535)]
        [int32]
        $ThrottleLimit = 32,
 
        [Parameter(Position=2)]
        [ValidateRange(1,65535)]
        [int32]
        $Timeout = 120,
 
        [Parameter(Position=3)]
        [switch]
        $ShowProgress,
 
        [Parameter(Position=4)]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        Write-Verbose -Message 'Creating local hostname list'
        $IPAddresses = [net.dns]::GetHostAddresses($env:COMPUTERNAME) | Select-Object -ExpandProperty IpAddressToString
        $HostNames = $IPAddresses | ForEach-Object {
            try {
                [net.dns]::GetHostByAddress($_)
            } catch {
                # We do not care about errors here...
            }
        } | Select-Object -ExpandProperty HostName -Unique
        $LocalHost = @('', '.', 'localhost', $env:COMPUTERNAME, '::1', '127.0.0.1') + $IPAddresses + $HostNames
 
        Write-Verbose -Message 'Creating initial variables'
        $runspacetimers       = [HashTable]::Synchronized(@{})
        $runspaces            = New-Object -TypeName System.Collections.ArrayList
        $bgRunspaceCounter    = 0
        
        Write-Verbose -Message 'Creating Initial Session State'
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($ExternalVariable in ('runspacetimers', 'Credential', 'LocalHost'))
        {
            Write-Verbose -Message "Adding variable $ExternalVariable to initial session state"
            $iss.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $ExternalVariable, (Get-Variable -Name $ExternalVariable -ValueOnly), ''))
        }
 
        Write-Verbose -Message 'Creating runspace pool'
        $rp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
        $rp.Open()
 
        Write-Verbose -Message 'Defining background runspaces scriptblock'
        $ScriptBlock = {
            [CmdletBinding()]
            Param
            (
                [Parameter(Position=0)]
                [string]
                $ComputerName,
 
                [Parameter(Position=1)]
                [int]
                $bgRunspaceID
            )
            $runspacetimers.$bgRunspaceID = Get-Date
            
            # Use this little embedded function later to join a bunch of wmi result properies to our final result object
            function Join-Object ($inputobj, $objtoadd, $prefix) {
                $result = $inputobj
                foreach($prop in $objtoadd | get-member -type Properties | select -expand Name) {
                    Add-Member -in $result -type NoteProperty -name "$($prefix)$($prop)" -value $objtoadd.($prop)
                }
                $result
            }

            function Prefix-StringArray ($array, $prefix) {
                $result = [String[]]@()
                foreach($item in $array) {
                    $result = $result + "$($prefix)$($item)"
                }
                $result
            }
            
            if (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -ErrorAction SilentlyContinue)
            {
                try
                {
                    Write-Verbose -Message "WMI Query: $ComputerName"
                    $WMIHast = @{
                        ComputerName = $ComputerName
                        ErrorAction = 'Stop'
                    }
                    if ($LocalHost -notcontains $ComputerName)
                    {
                        $WMIHast.Credential = $Credential
                    }
                    $WMI_OSProps          = @('BuildNumber','Version','SerialNumber','ServicePackMajorVersion','CSDVersion','SystemDrive',`
                                              'SystemDirectory','WindowsDirectory','Caption','TotalVisibleMemorySize','FreePhysicalMemory',`
                                              'TotalVirtualMemorySize','FreeVirtualMemory','OSArchitecture','Organization','LocalDateTime',`
                                              'RegisteredUser','OperatingSystemSKU','OSType','LastBootUpTime','InstallDate')
                    $prefix_OSProps       = 'OS_'
                    $WMI_ProcProps        = @('Name','Description','MaxClockSpeed','CurrentClockSpeed','AddressWidth','NumberOfCores','NumberOfLogicalProcessors')
                    $prefix_ProcProps     = 'CPU_'
                    $WMI_CompProps        = @('DNSHostName','Domain','Manufacturer','Model','NumberOfLogicalProcessors','NumberOfProcessors','PrimaryOwnerContact', `
                                              'PrimaryOwnerName','SystemType','TotalPhysicalMemory')
                    $prefix_CompProps     = 'System_'
                    $WMI_ChassisProps     = @('ChassisTypes','Manufacturer','SerialNumber','Tag','SKU')
                    $prefix_ChassisProps  =   'Chassis_'
                    $WMI_MemProps         = @('BankLabel','DeviceLocator','Capacity','PartNumber','Speed','Tag')
                    $prefix_MemProps      = 'Memory_'
                    $WMI_MemArrayProps    = @('Tag','MemoryDevices','MaxCapacity')
                    $prefix_MemArrayProps = 'MemoryArray_'
                    $WMI_NetProps         = @('Description', 'DHCPServer','IpAddress','IpSubnet','DefaultIPGateway','DNSServerSearchOrder','WinsPrimaryServer', `
                                              'WinsSecondaryServer')
                    $prefix_NetProps      = 'Net_'
                    # Modify this variable to change your default set of display properties
                    $defaultProperties    = @('ComputerName','OSCaption','OSServicePack','OSVersion','OSSKU','Architecture', `
                                              'PhysicalMemoryTotal','PhysicalMemoryFree','VirtualMemoryTotal','VirtualMemoryFree', `
                                              'CPUCores','CPUSockets','MemorySlotsTotal','MemorySlotsUsed','SystemTime', `
                                              'LastBootTime','InstallDate','Uptime')
                    $SKUs                 = @("Undefined","Ultimate Edition","Home Basic Edition","Home Basic Premium Edition","Enterprise Edition",`
                                              "Home Basic N Edition","Business Edition","Standard Server Edition","DatacenterServer Edition","Small Business Server Edition",`
                                              "Enterprise Server Edition","Starter Edition","Datacenter Server Core Edition","Standard Server Core Edition",`
                                              "Enterprise ServerCoreEdition","Enterprise Server Edition for Itanium-Based Systems","Business N Edition","Web Server Edition",`
                                              "Cluster Server Edition","Home Server Edition","Storage Express Server Edition","Storage Standard Server Edition",`
                                              "Storage Workgroup Server Edition","Storage Enterprise Server Edition","Server For Small Business Edition","Small Business Server Premium Edition")
                    $ChassisModels        = @("PlaceHolder","Maybe Virtual Machine","Unknown","Desktop","Thin Desktop","Pizza Box","Mini Tower","Full Tower","Portable",`
                                              "Laptop","Notebook","Hand Held","Docking Station","All in One","Sub Notebook","Space-Saving","Lunch Box","Main System Chassis",`
                                              "Lunch Box","SubChassis","Bus Expansion Chassis","Peripheral Chassis","Storage Chassis" ,"Rack Mount Unit","Sealed-Case PC")
                    
                    # Collect all of our wmi data
                    $wmi_compsystem = Get-WmiObject @WMIHast -Class Win32_ComputerSystem | select $WMI_CompProps
                    $wmi_os = Get-WmiObject @WMIHast -Class Win32_OperatingSystem | select $WMI_OSProps
                    $wmi_proc = Get-WmiObject @WMIHast -Class Win32_Processor | select $WMI_ProcProps
                    $wmi_chassis = Get-WmiObject @WMIHast -Class Win32_SystemEnclosure | select $WMI_ChassisProps
                    $wmi_memory = Get-WmiObject @WMIHast -Class Win32_PhysicalMemory | select $WMI_MemProps
                    $wmi_memoryarray = Get-WmiObject @WMIHast -Class Win32_PhysicalMemoryArray | select $WMI_MemArrayProps
                    $wmi_net = Get-WmiObject @WMIHast -Class Win32_NetworkAdapterConfiguration | select $WMI_NetProps
                    
                    ## Calculated properties
                    # CPU count
                    if (@($wmi_proc)[0].NumberOfCores) #Modern OS
                    {
                        $Sockets = @($wmi_proc).Count
                        $Cores = ($wmi_proc | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                    }
                    else #Legacy OS
                    {
                        $Sockets = @($wmi_proc | Select-Object -Property SocketDesignation -Unique).Count
                        $Cores = @($wmi_proc).Count
                    }
                    
                    # OperatingSystemSKU is not availble in 2003 and XP
                    if ($wmi_os.OperatingSystemSKU -ne $null)
                    {
                        $OS_SKU = $SKUs[$wmi_os.OperatingSystemSKU]
                    }
                    else
                    {
                        $OS_SKU = 'Not Available'
                    }
                    $System_Time = ([wmi]'').ConvertToDateTime($wmi_os.LocalDateTime).tostring("dd/MM/yyyy HH:mm:ss")
                    $OS_LastBoot = ([wmi]'').ConvertToDateTime($wmi_os.LastBootUptime).tostring("dd/MM/yyyy HH:mm:ss")
                    $OS_InstallDate = ([wmi]'').ConvertToDateTime($wmi_os.InstallDate).tostring("dd/MM/yyyy HH:mm:ss")
                    $Uptime = New-TimeSpan -Start $OS_LastBoot -End $System_Time                    
                    $Memory_Slotstotal = 0
                    $Memory_SlotsUsed = (@($wmi_memory)).Count                
                    @($wmi_memoryarray) | % {$Memory_Slotstotal = $Memory_Slotstotal + $_.MemoryDevices}
                    
                    #region Create custom output object
                    #Due to some bug setting scriptblock directly as value can cause 'NullReferenceException' in v3 host
                    $ReadableOutput = @{
                        Name = 'ToString'
                        MemberType = 'ScriptMethod'
                        PassThru = $true
                        Force = $true
                        Value = [ScriptBlock]::Create(@"
                            "{0:N1} {1}" -f @(
                                switch -Regex ([math]::Log(`$this,1024)) {
                                    ^0 {
                                        (`$this / 1), ' B'
                                    }
                                    ^1 {
                                        (`$this / 1KB), 'KB'
                                    }
                                    ^2 {
                                        (`$this / 1MB), 'MB'
                                    }
                                    ^3 {
                                        (`$this / 1GB), 'GB'
                                    }
                                    ^4 {
                                        (`$this / 1TB), 'TB'
                                    }
                                    default {
                                        (`$this / 1PB), 'PB'
                                    }
                                }
                            )
"@
                        )
                    }

                    $myObject = New-Object -TypeName PSObject -Property @{
                        ### Defaults
                        'PSComputerName' = $ComputerName
                        'ComputerName' = $wmi_compsystem.DNSHostName                        
                        'OSCaption' = $wmi_os.Caption
                        'OSServicePack' = $wmi_os.ServicePackMajorVersion
                        'OSVersion' = $wmi_os.Version
                        'OSSKU' = $OS_SKU
                        'Architecture' = $wmi_os.OSArchitecture
                        'PhysicalMemoryTotal' = $wmi_os.TotalVisibleMemorySize | Add-Member @ReadableOutput
                        'PhysicalMemoryFree' = $wmi_os.FreePhysicalMemory | Add-Member @ReadableOutput
                        'VirtualMemoryTotal' = $wmi_os.TotalVirtualMemorySize | Add-Member @ReadableOutput
                        'VirtualMemoryFree' = $wmi_os.FreeVirtualMemory | Add-Member @ReadableOutput
                        'CPUCores' = $Cores
                        'CPUSockets' = $Sockets
                        'MemorySlotsTotal' = $Memory_Slotstotal
                        'MemorySlotsUsed' = $Memory_SlotsUsed
                        'SystemTime' = $System_Time
                        'LastBootTime' = $OS_LastBoot
                        'InstallDate' = $OS_InstallDate
                        'Uptime' = "$($Uptime.days) days $($Uptime.hours) hours $($Uptime.minutes) minutes"
                    }

                    # Add in all the other wmi properties we gathered just in case anyone wants 'em
                    $myObject = Join-Object $myObject $wmi_compsystem $prefix_CompProps
                    $myObject = Join-Object $myObject $wmi_os $prefix_OSProps
                    $myObject = Join-Object $myObject $wmi_proc $prefix_ProcProps
                    $myObject = Join-Object $myObject $wmi_chassis $prefix_ChassisProps
                    $myObject = Join-Object $myObject $wmi_memory $prefix_MemProps
                    $myObject = Join-Object $myObject $wmi_memoryarray $prefix_MemArrayProps
                    $myObject = Join-Object $myObject $wmi_net $prefix_NetProps

                    # Setup the default properties for output
                    $myObject.PSObject.TypeNames.Insert(0,'My.Asset.Info')
                    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
                    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
                    $myObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers
                    #endregion
                    
                    # Add property sets for your convenience
                    $myObject | Add-Member PropertySet "Default" ([string[]]@($defaultProperties))
                    $myObject | Add-Member PropertySet "OS" ([string[]]@(Prefix-StringArray $WMI_OSProps $prefix_OSProps))
                    $myObject | Add-Member PropertySet "System" ([string[]]@(Prefix-StringArray $WMI_CompProps $prefix_CompProps))
                    $myObject | Add-Member PropertySet "Processor" ([string[]]@(Prefix-StringArray $WMI_ProcProps $prefix_ProcProps))
                    $myObject | Add-Member PropertySet "Chassis" ([string[]]@(Prefix-StringArray $WMI_ChassisProps $prefix_ChassisProps))
                    $myObject | Add-Member PropertySet "Memory" ([string[]]@(Prefix-StringArray $WMI_MemProps $prefix_MemProps))
                    $myObject | Add-Member PropertySet "MemoryArray" ([string[]]@(Prefix-StringArray $WMI_MemArrayProps $prefix_MemArrayProps))
                    $myObject | Add-Member PropertySet "Network" ([string[]]@(Prefix-StringArray $WMI_NetProps $prefix_NetProps))

                    Write-Output -InputObject $myObject
                }
                catch
                {
                    Write-Warning -Message ('{0}: {1}' -f $ComputerName, $_.Exception.Message)
                }
            }
            else
            {
                Write-Warning -Message ("{0}: Unavailable" -f $ComputerName)
            }
        }
 
        function Get-Result
        {
            [CmdletBinding()]
            Param 
            (
                [switch]$Wait
            )
            do
            {
                $More = $false
                foreach ($runspace in $runspaces)
                {
                    $StartTime = $runspacetimers.($runspace.ID)
                    if ($runspace.Handle.isCompleted)
                    {
                        Write-Verbose -Message ('Thread done for {0}' -f $runspace.IObject)
                        $runspace.PowerShell.EndInvoke($runspace.Handle)
                        $runspace.PowerShell.Dispose()
                        $runspace.PowerShell = $null
                        $runspace.Handle = $null
                    }
                    elseif ($runspace.Handle -ne $null)
                    {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime)
                    {
                        if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $runspace.PowerShell)
                        {
                            Write-Warning -Message ('Timeout {0}' -f $runspace.IObject)
                            $runspace.PowerShell.Dispose()
                            $runspace.PowerShell = $null
                            $runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($threat in $runspaces.Clone())
                {
                    if ( -not $threat.handle)
                    {
                        Write-Verbose -Message ('Removing {0} from runspaces' -f $threat.IObject)
                        $runspaces.Remove($threat)
                    }
                }
                if ($ShowProgress)
                {
                    $ProgressSplatting = @{
                        Activity = 'Getting asset info'
                        Status = '{0} of {1} total threads done' -f ($bgRunspaceCounter - $runspaces.Count), $bgRunspaceCounter
                        PercentComplete = ($bgRunspaceCounter - $runspaces.Count) / $bgRunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        }
    }
    Process
    {
        foreach ($Computer in $ComputerName)
        {
            $bgRunspaceCounter++
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameter('bgRunspaceID',$bgRunspaceCounter).AddParameter('ComputerName',$Computer)
            $psCMD.RunspacePool = $rp
 
            Write-Verbose -Message ('Starting {0}' -f $Computer)
            [void]$runspaces.Add(@{
                Handle = $psCMD.BeginInvoke()
                PowerShell = $psCMD
                IObject = $Computer
                ID = $bgRunspaceCounter
           })
           Get-Result
        }
    }
 
    End
    {
        Get-Result -Wait
        if ($ShowProgress)
        {
            Write-Progress -Activity 'Getting asset info' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Closing runspace pool"
        $rp.Close()
        $rp.Dispose()
    }
}

function Convert-BinaryToHex 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]
        [string]$Binary
    )
    Begin {
        #Create binary empty collection
        [string[]]$TextArray = @()        
    }
    Process {
        #Split Binary string into array
        $BinaryArray = $Binary -split '\s'
            
        #Convert each item to Char
        ForEach ($a in $BinaryArray) 
        {
            $a = [char]([convert]::ToInt64($a,2))
            $TextArray += "0x$(([convert]::ToString([int][char]$a,16)).PadLeft(8,'0'))"
        }
    }
    End {
        #Write out hex string
        [string]::Join(' ',$TextArray)        
    }
}     

function Convert-TextToBinary 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]    
        [string]$Text
    )
    Begin {
        #Create binary empty collection
        [string[]]$BinaryArray = @()
    }
    Process {
        #Convert text to array
        $TextArray = $Text.ToCharArray()
            
        #Convert each item to binary
        ForEach ($a in $TextArray) 
        {
            $BinaryArray += ([convert]::ToString([int][char]$a,2)).PadLeft(8,'0')
        }
    }
    End {
        #Write out binary string
        [string]::Join(' ',$BinaryArray)
    }
}

function Convert-HexToBinary 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]
        [string]$Hex
    )
    Begin {
        #Create binary empty collection
        [string[]]$binarr = @()        
    }
    Process {
        #Split Binary string into array
        $HexArray = $Hex -split '\s'
            
        #Convert each item to Char
        ForEach ($a in $HexArray) 
        {
            $a = ([char]([convert]::ToInt64($a.TrimStart('x0'),16)))
            $binarr += ([convert]::ToString([int][char]$a,2)).PadLeft(8,'0')
        }
    }
    End {
        #Write out binary string
        [string]::Join(' ',$binarr)        
    }
}

function Convert-BinaryToText 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]
        [string]$Binary
    )
    Begin {
        #Create binary empty collection
        [string[]]$TextArray = @()        
    }
    Process {
        #Split Binary string into array
        $BinaryArray = $Binary -split '\s'
            
        #Convert each item to Char
        ForEach ($a in $BinaryArray) 
        {
            $TextArray += [char]([convert]::ToInt64($a,2))
        }
    }
    End {
        #Write out text string
        [string]::Join('',$TextArray)        
    }
}

function Convert-HexToText 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]
        [string]$Hex
    )
    Begin {
        #Create text empty collection
        [string[]]$textarr = @()        
    }
    Process {
        #Split Binary string into array
        $HexArray = $Hex -split '\s'
            
        #Convert each item to Char
        ForEach ($a in $HexArray) 
        {
            $textarr += [char]([convert]::ToInt64($a.TrimStart('x0'),16))
        }
    }
    End {
        #Write out text string
        [string]::Join('',$textarr)        
    }
}  

function Convert-TextToHex 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = 'True')]    
        [string]$Text
    )
    Begin   {
        #Create hex empty collection
        [string[]]$HexArray = @()
    }
    Process {
        #Convert text to array
        $textarr = $Text.ToCharArray()
            
        #Convert each item to binary
        ForEach ($a in $textarr) 
        {
            $HexArray += "0x$(([convert]::ToString([int][char]$a,16)).PadLeft(8,'0'))"
        }
    }
    End {
        #Write out hex string
        [string]::Join(' ',$HexArray)
    }
}

function Get-ProfilePath 
{
    ($PROFILE).psobject.Properties |
    Where-Object {
        $_.name -match 'a|c'
    } |
    Select-Object name, value
}

function Set-RotateImage 
{
    <#
            Set-RotateImage -Mode Rotate180FlipNone -File $(gci c:\ -Filter '*.bmp').FullName -Verbose
            Set-RotateImage -Mode Rotate180FlipNone -File c:\test.bmp -Help -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0,ValueFromPipeline = $true)]
        [ValidateScript({
                    $([Regex]::Match($_,'\w+$').Value) -match '^(BMP|GIF|JPEG|PNG|TIFF|WMF)$'
        })][String[]]$file,
        [Parameter(Mandatory = $false,Position = 1)]
        [ValidateSet('RotateNoneFlipNone',
                'Rotate90FlipNone',
                'Rotate180FlipNone',
                'Rotate270FlipNone',
                'RotateNoneFlipX',
                'Rotate90FlipX',
                'Rotate180FlipX',
                'Rotate270FlipX',
                'RotateNoneFlipY',
                'Rotate90FlipY',
                'Rotate180FlipY',
                'Rotate270FlipY',
                'RotateNoneFlipXY',
                'Rotate90FlipXY',
                'Rotate180FlipXY',
                'Rotate270FlipXY' 
        )][String]$Mode,
        [Parameter(Mandatory = $false,Position = 2)][Switch]$Help
    )
    BEGIN
    {
        $Info = @(
            [PSCustomObject]@{
                'Name'      = 'RotateNoneFlipNone'
                'Description' = 'Uses no rotation and no flipping'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate90FlipNone'
                'Description' = 'Uses a 90-degree rotation without flipping.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate180FlipNone'
                'Description' = 'Uses a 180-degree rotation without flipping.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate270FlipNone'
                'Description' = 'Uses a 270-degree rotation without flipping.'
            }
            [PSCustomObject]@{
                'Name'      = 'RotateNoneFlipX'
                'Description' = 'Uses no rotation followed by a horizontal flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate90FlipX'
                'Description' = 'Uses a 90-degree rotation followed by a horizontal flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate180FlipX'
                'Description' = 'Uses a 180-degree rotation followed by a horizontal flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate270FlipX'
                'Description' = 'Uses a 270-degree rotation followed by a horizontal flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'RotateNoneFlipY'
                'Description' = 'Uses no rotation followed by a vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate90FlipY'
                'Description' = 'Uses a 90-degree rotation followed by a vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate180FlipY'
                'Description' = 'Uses a 180-degree rotation followed by a vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate270FlipY'
                'Description' = 'Uses a 270-degree rotation followed by a vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'RotateNoneFlipXY'
                'Description' = 'Uses no rotation followed by a horizontal and vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate90FlipXY'
                'Description' = 'Uses a 90-degree rotation followed by a horizontal and vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate180FlipXY'
                'Description' = 'Uses a 180-degree rotation followed by a horizontal and vertical flip.'
            }
            [PSCustomObject]@{
                'Name'      = 'Rotate270FlipXY'
                'Description' = 'Uses a 270-degree rotation followed by a horizontal and vertical flip.'
        })
    }
    PROCESS
    {
        if(-not($Help))
        {
            foreach ($ImageFile in $file)
            {
                if (Test-Path $ImageFile)
                {
                    $ImageFile = Convert-Path $ImageFile
                    Write-Verbose "Working on $ImageFile"
                    $Ext = $([Regex]::Match($ImageFile,'\w+$').Value)
                    $PicObj = New-Object System.Drawing.Bitmap -ArgumentList ($ImageFile)
                    $PicObj.RotateFlip($Mode)
                    $PicObj.Save("$($ImageFile)_TMP",$Ext)
                    $PicObj.Dispose()
                    [void](Remove-Item $ImageFile -Force)
                    [void](Rename-Item "$($ImageFile)_TMP" -NewName $ImageFile -Force)
                }
                else
                {
                    Write-Verbose "File $ImageFile not found."
                }
            }
        }
        else
        {
            if ($Mode)
            {
                Write-Output $Info |
                Where-Object {
                    $_.Name -eq $Mode
                } |
                Format-Table -AutoSize -Wrap
            }
            else
            {
                Write-Output $Info | Format-Table -AutoSize -Wrap
            }
        }
    }
    END
    {}
}

function Convert-ImageFormat 
{
    <#
            gci c:\Images -Filter '*.bmp' -Recurse | Convert-ImageFormat -Verbose
            PS C:\> Convert-ImageFormat -File C:\1.BMP,C:\2.BMP -Format JPEG -Verbose
            ПОДРОБНО: Converting C:\1.BMP to C:\1.JPEG
            ПОДРОБНО: Converting C:\2.BMP to C:\2.JPEG
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0,ValueFromPipeline = $true)][ValidateScript({
                    $([Regex]::Match($_,'\w+$').Value) -match '^(BMP|GIF|JPEG|JPG|PNG|TIFF|WMF)$'
        })][String[]]$File,
        [Parameter(Mandatory = $false,Position = 1)][ValidateSet('BMP','GIF','JPEG','PNG','TIFF','WMF')][String]$Format = 'JPEG'
    )

    if ($input)
    {
        $File = $input.FullName
    }
    $File = Convert-Path $File
    foreach ($FilePath in $File) 
    {
        if (Test-Path $FilePath)
        {
            if ($([Regex]::Match($FilePath,'\w+$').Value) -ne $Format)
            {
                [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
                $ConvertFile = New-Object System.Drawing.Bitmap -ArgumentList $FilePath
                $NewfilName = "$($FilePath -replace '\.\w+$').$Format"
                $ConvertFile.Save($NewfilName, $Format)
                Write-Verbose "Converting $FilePath to $NewfilName"
                $ConvertFile.Dispose()
            }
            else
            {
                Write-Verbose 'Source file is the same as output file format. Skipped.'
            }
        }
        else
        {
            Write-Verbose "File $FilePath not found."
        }
    }
}

function Get-Screenshot 
{
    #Get-Screenshot -wait 3 -SendEmailOnCompletion -Format PNG -FileMask (Get-Date).ToShortDateString()
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][String]$OutputFolder = $PWD,
        [Parameter(Mandatory = $false,Position = 1)][ValidateSet('BMP','GIF','JPEG','PNG','TIFF','WMF')][String]$Format = 'JPEG',
        [Parameter(Mandatory = $false,Position = 2)][String]$FileMask = $(Get-Date -UFormat '%d-%m-%Y-%H-%M-%S'),
        [Parameter(Mandatory = $false,Position = 3)][Int]$Wait = 0,
        [Parameter(Mandatory = $false,Position = 4)][String]$Body = 'Hello!<br></br>Please check attachments.',
        [Parameter(Mandatory = $false)][Switch]$InvokeOnCompletion,
        [Parameter(Mandatory = $false)][Switch]$SendEmailOnCompletion
    )
    BEGIN
    {
        [void][Reflection.Assembly]::LoadWithPartialName('System.Drawing')
        [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        $OutputFolder = Convert-Path $OutputFolder
        $Path = $OutputFolder -replace "$($OutputFolder -replace '^.*\\+?')"
        Write-Verbose "OutputFolder set to $Path"
        if (-not(Test-Path -Path $Path))
        {
            [void](New-Item -Path $Path -ItemType Directory -Force -Confirm:$false)
            Write-Verbose "Directory $Path created."
        }
    }
    PROCESS
    {
        if ($Wait -gt 0)
        {
            Write-Verbose "Screenshot will be taken in $Wait seconds."
            Start-Sleep -Seconds $Wait
        }
        $Bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $Screenshot = New-Object System.Drawing.Bitmap -ArgumentList $Bounds.Width, $Bounds.Height
        $Graphics = [System.Drawing.Graphics]::FromImage($Screenshot)
        $Graphics.CopyFromScreen($Bounds.Location, [System.Drawing.Point]::Empty, $Bounds.Size)
        $OutputFile = "$(Join-Path $OutputFolder -ChildPath $FileMask).$Format"
        try
        {
            $Screenshot.Save($OutputFile)
            Write-Verbose "Screenshot saved to $OutputFile"
        }
        catch
        {
            Write-Warning "Error saving screenshot to $OutputFile`n$_"
            break
        }
    }
    END
    {
        $Graphics.Dispose()
        $Screenshot.Dispose()
        if($InvokeOnCompletion)
        {
            Invoke-Item $OutputFile -Confirm:$false
        }
        if($SendEmailOnCompletion)
        {
            if($EmailSettings)
            {
                try
                {
                    Send-MailMessage @EmailSettings -Attachments $OutputFile -BodyAsHtml -Subject "$Body"
                    Write-Verbose "Email with attachment successfully sent to $($EmailSettings.To -join ',')"
                }
                catch
                {
                    Write-Warning "Error sending email`n$_"
                }
            }
            else
            {
                Write-Warning 'You need to define EmailSettings variable in order to use this feature.'
            }
        }
    }
}

function Get-ClassConstructors
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0)][Type]$Class
    )
    $results = @(iex ("[$Class].GetConstructors()") |
        ForEach-Object {
            ($_.GetParameters() |
            ForEach-Object {
            ‘{0} {1}’ -f $_.Name, $_.ParameterType.FullName
            }) -join ‘,’
        }
    )
    $i=0
    if ($results)
    {
        $i++
        $x=0
        Write-host $("Constructor #{0}" -f $i)
        foreach ($result in $results)
        {
            #$colors = New-Object System.Collections.ArrayList
            #$colors.AddRange(@('Black','Blue','Cyan','DarkBlue','DarkCyan','DarkGray','DarkGreen','DarkMagenta','DarkRed','DarkYellow','Green','Magenta','Red','Yellow'))
            Write-Verbose $result
            $result -split ',' | % {
                $item = $_
                $x++
                <#
                $color = Get-Random -InputObject $colors
                Write-Host "Object #$x`t" -NoNewline
                Write-Host -Object $item -BackgroundColor White -ForegroundColor $color
                $colors.Remove($color)
                #>
                Write-Host "Object #$x`t" -NoNewline
                Write-Host -Object $item -BackgroundColor DarkGreen
            }
        }
    }

}

function Import-Class 
{
    <#
            EXAMPLE 1
            Import-Class -Class Math -Verbose
            Sin 90
            Round (Sin 90),2
            Round $([decimal]'45.948021124'),2
            Round $([decimal]'45.948021124'),4
            EXAMPLE 2
            Import-Class -Class System.Text.Encoding -Verbose
            GetEncodings | ft -AutoSize -Wrap
            EXAMPLE 3
            Import-Class -Class System.Globalization.DateTimeFormatInfo -Type Property -Verbose
            CurrentInfo
            EXAMPLE 4
            Import-Class -Class Math -Type Property -Verbose
            PI
            Import-Class -Class Math -Type Property -Prefix -Verbose
            Math-PI
            EXAMPLE 5
            Import-Class -Class ([System.Drawing.Color]) -Type Property -Verbose -Prefix
            PS C:\> Color-Green


            R             : 0
            G             : 128
            B             : 0
            A             : 255
            IsKnownColor  : True
            IsEmpty       : False
            IsNamedColor  : True
            IsSystemColor : False
            Name          : Green
            EXAMPLE 6
            Import-Class system.io.path
            Import-Class guid
            NewGuid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0,ParameterSetName = 'Get')][Type]$Class,
        [Parameter(Mandatory = $false,Position = 1,ParameterSetName = 'Get')][ValidateSet('Method','Property')][String]$Type = 'Method',
        [Parameter(Mandatory = $false,Position = 2,ParameterSetName = 'Get')][ValidateSet('Global','Local','Script','Private')][String]$Scope = 'Global',
        [Parameter(Mandatory = $false,Position = 3,ParameterSetName = 'Get')][Switch]$Prefix,
        [Parameter(Mandatory = $false,Position = 4,ParameterSetName = 'List')][Switch]$ListAvailiable
    )
    if (-not($ListAvailiable))
    {
        $Class |
        Get-Member -Static |
        Where-Object {
            $_.MemberType -eq $Type
        }| 
        ForEach-Object {
            $Item = $_
            if($prefix)
            {
                $Name = "$($Item.TypeName -replace '^.*\.+?')-$($_.Name)"
            }
            else
            {
                $Name = $($_.Name)
            }
            $Import = "Function:$($Scope):$Name"
            if (Test-Path $Import) 
            {
                Remove-Item $Import -Force -Confirm:$false
            }
            switch ($Type)
            {
                'Method'
                {
                    [void](New-Item $Import -Value "[$($Class.FullName)].InvokeMember('$($Item.Name)','Public,Static,InvokeMethod,DeclaredOnly', `$null, `$null, `$args[0])" -Force)
                }
                'Property'
                {
                    [void](New-Item $Import -Value "[$($Item.TypeName)]::$($Item.Name)" -Force)
                }
            }
            Write-Verbose "Imported $Name function with $Scope scope."
        }
    }
    else
    {
        Write-Verbose 'Getting availiable types'
        [System.AppDomain]::CurrentDomain.GetAssemblies() |
        ForEach-Object {
            $_.GetTypes()
        } |
        Sort-Object basetype
    }
}

function Set-Wallpaper 
{
    ##    Set-Wallpaper "C:\Users\Joel\Images\Wallpaper\Dual Monitor\mandolux-tiger.jpg" "Tile"
    ##    ls *.jpg | get-random | Set-Wallpaper
    ##    ls *.jpg | get-random | Set-Wallpaper -Style "Stretch"
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [ValidateScript({
                    [System.IO.Path]::GetExtension($_).Remove(0,1) -match 'BMP|JPEG|JPG'
        })]#seems like PNG is not a valid option
        [string]$Path,
        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateSet('NoChange','Tile','Center','Stretch')]
        [string]$Style = 'NoChange'
    )
    BEGIN {
        try 
        {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
   public enum Style : int
   {
       Tile, Center, Stretch, NoChange
   }

   public class Setter {
      public const int SetDesktopWallpaper = 20;
      public const int UpdateIniFile = 0x01;
      public const int SendWinIniChange = 0x02;

      [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
      private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
      
      public static void SetWallpaper ( string path, Wallpaper.Style style ) {
        RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
         switch( style )
         {
            case Style.Stretch :
               key.SetValue(@"WallpaperStyle", "2") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Center :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "0") ; 
               break;
            case Style.Tile :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "1") ;
               break;
            case Style.NoChange :
               break;
         }
         key.Close();
         SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
      }
   }
}
"@
            $WP = [Wallpaper.Setter]
        } 
        catch 
        {
            Write-Warning 'Ошибка загрузки типа'
        }
    }
    PROCESS {
        ## you may consider $path_as_path = [IO.Path]::GetFullPath( $Path ) instead of $(Convert-Path $Path)
        Write-Verbose "Setting Wallpaper ($Style) to $(Convert-Path $Path)"
        $WP::SetWallpaper( (Convert-Path $Path), [Wallpaper.Style]::$Style )
    }
    END{}
}

function Remove-FileFromRepositores 
{
    [CmdletBinding()]

    param(
        [Parameter(Mandatory = $true,Position = 0)][ValidateScript({
                    Test-Path -Path $_ -IsValid
        })][string]$File
    )
    $Repository = 'S:\Kirill', 'C:\inetpub\powershell\Kirill\programs', 'C:\Users\Pashkov-KM\Documents\PowerShell\Programs\My programs'
    foreach ($Path in $Repository)
    {
        try 
        {
            if (Test-Path "$Path\$File")
            {
                Remove-Item -Path "$Path\$File" -Confirm:$false -ErrorAction Stop
                Write-Verbose "Удален файл $Path\$File"
            }
            else
            {
                Write-Verbose "Файл $Path\$File не существует"
            }
        }
        catch
        {
            Write-Warning "Ошибка удаления файла $Path\$File"
        }
    }
}

function Copy-FileToRepositores 
{
    [CmdletBinding()]

    param(
        [Parameter(Mandatory = $true,Position = 0)][ValidateScript({
                    Test-Path -Path $_
        })][string]$File
    )
    $Repository = 'S:\Kirill', 'C:\inetpub\powershell\Kirill\programs', 'C:\Users\Pashkov-KM\Documents\PowerShell\Programs\My programs'
    foreach ($Path in $Repository)
    {
        try 
        {
            Copy-Item -Path $File -Destination $Path -Force -Confirm:$false -ErrorAction Stop
            Write-Verbose "Скопирован файл $File в $Path"
        }
        catch
        {
            Write-Warning "Ошибка копирвания файла $File в $Path"
        }
    }
}

function ConvertFrom-Base64 
{
    param($str,[validateset('Unicode','UTF7','UTF8','UTF32','Default','ASCII')]$code = 'Unicode') 
    [system.text.encoding]::$code.getstring( [system.convert]::frombase64string($str))
}

function ConvertTo-Base64 
{
    param($str,[validateset('Unicode','UTF7','UTF8','UTF32','Default','ASCII')]$code = 'Unicode')
    [system.convert]::tobase64string([system.text.encoding]::$code.getBytes($str))
}

function Import-ZipArchive 
{
    #.NET 4.5 or above
    #Import-ZipArchive -SourceFolder C:\NLog -DestinationFolder c:\
    #Import-ZipArchive -SourceFolder C:\NLog -DestinationFolder c:\ -Name test
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0,
                HelpMessage = "Specify source file or folder that have to be archived, example1: 'c:\mydata' or 'c:\videso\MOV01.avi'",
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    Test-Path $_ -PathType Any
        })] 
        [Alias('Src')]
        [string]$Source,
        [Parameter(Mandatory = $false,Position = 1,
                HelpMessage = "Specify destination folder for creating archive file, example: 'c:\tmp",
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    Test-Path $_ -PathType Container
        })] 
        [Alias('ToFolder')]
        [Alias('Dst')]
        [string]$DestinationFolder = $PWD.Path,
        [Parameter(Mandatory = $false,Position = 2,
                HelpMessage = 'Specify archive file name',
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('File')]
        [string]$Name,
        [Parameter(Mandatory = $false,Position = 3,
        HelpMessage = 'Specify compression level')]
        [ValidateSet('Fastest','NoCompression','Optimal')]
        [string]$CompressionLevel = 'Optimal',
        [Parameter(Mandatory = $false,Position = 4,
        HelpMessage = 'Specify encoding')]
        [ValidateSet('Default','Unicode','UTF8')]
        [Alias('Encode')]
        [String]$CodePage = 'Default',
        [Parameter(Mandatory = $false,Position = 5,
        HelpMessage = 'Specify either to overwrite existing file or not')]
        [Alias('Force')]
        [switch]$Overwrite,
        [Parameter(Mandatory = $false,Position = 6,
        HelpMessage = 'Specify Remove switch to remove source folder on successful archive creating')]
        [Alias('Delete')]
        [switch]$Remove,
        [Parameter(Mandatory = $false,Position = 7,
        HelpMessage = 'Specify IncludeBaseDirectory switch to include base directory to archive file')]
        [Alias('Include')]
        [switch]$IncludeBaseDirectory
    )
    BEGIN
    {
        try
        {
            Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
            Write-Verbose "Загружена сборка 'System.IO.Compression.FileSystem'"
        }
        catch
        {
            Write-Warning "Не удалось загрузить сборку 'System.IO.Compression.FileSystem'"
        }
    }#begin
    PROCESS
    {
        if(-not$DestinationFolder)
        {
            $DestinationFolder = (Get-ItemProperty $Source).Directory
        }
        if($IncludeBaseDirectory)
        {
            $BaseFolder = $true
        }
        else
        {
            $BaseFolder = $false
        }
        if (-not($Name))
        {
            $Name = $(Get-ItemProperty -Path $Source | Select-Object -ExpandProperty BaseName)
        }
        $DstFile = "$(Join-Path -Path $DestinationFolder -ChildPath $Name).zip"
        if (Test-Path -Path $DstFile -PathType Leaf)
        {
            if ($Overwrite)
            {
                try
                {
                    Remove-Item -Path $DstFile -Force -Confirm:$false
                }
                catch
                {
                    Write-Warning "Не удалось удалить существующий файл $DstFile"
                    break
                }
            }
            else
            {
                Write-Warning "Файл $DstFile уже существует. Укажите другое имя или воспользуйтесь параметром -Overwrite чтобы перезаписать существующий файл."
                break
            }
        }
        if (Test-Path $Source -PathType Container)
        {
            try
            {
                $FSO = New-Object -ComObject  Scripting.FileSystemObject
                $SourceSize = '{0:N2} MB' -f $($FSO.GetFolder($Source).Size / 1MB)
                Write-Verbose "Выполняется архивирование:`nSource = $Source`nSourceSize = $SourceSize`nDestinationFile = $DstFile`nCompressionLevel = $CompressionLevel`nOverwrite = $(if ($Overwrite)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nRemove = $(if ($Remove)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nIncludeBaseDirectory = $(if ($IncludeBaseDirectory)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                
                
                
                
                
                })"
                [System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $DstFile,$CompressionLevel,$BaseFolder,$([System.Text.Encoding]::$CodePage))
                Write-Verbose "Архивирование $DstFile $(Get-ItemProperty $DstFile | Select-Object @{
                    l = 'Size'
                    e = {'({0:N2} MB)' -f $($_.Length / 1MB)
                    
                    
                    
                    
                    
                    }
                } | Select-Object -ExpandProperty Size) успешно выполнено"
                #Write-Output $true
            }
            catch
            {
                Write-Warning "Ошибка создания ахрива из директории`n`n$_`n`nSource = $Source`nSourceSize = $SourceSize`nDestinationFile = $DstFile`nCompressionLevel = $CompressionLevel`nOverwrite = $(if ($Overwrite)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nRemove = $(if ($Remove)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nIncludeBaseDirectory = $(if ($IncludeBaseDirectory)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                
                
                
                
                
                })"
            }
        }
        if (Test-Path $Source -PathType Leaf)
        {
            try
            {
                if($IncludeBaseDirectory)
                {
                    $Relative = (Resolve-Path $Source -Relative).TrimStart('.\')
                }
                else
                {
                    $Relative = [System.IO.Path]::GetFileName($Source)
                }
                $SourceSize = Get-ItemProperty -Path $Source |
                Select-Object @{
                    l = 'Size'
                    e = {
                        '{0:N2} MB' -f ($_.Length / 1MB)
                    }
                } |
                Select-Object -ExpandProperty Size
                Write-Verbose "Выполняется архивирование:`nSource = $Source`nSourceSize = $SourceSize`nCompressionLevel = $CompressionLevel`nOverwrite = $(if ($Overwrite)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nRemove = $(if ($Remove)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nIncludeBaseDirectory = $(if ($IncludeBaseDirectory)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                
                
                
                
                
                })"
                $Archive = [System.IO.Compression.ZipFile]::Open($DstFile, 'Update')
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($Archive, $Source, $Relative, $CompressionLevel)
                $Archive.Dispose()
                Write-Verbose "Архивирование $DstFile $(Get-ItemProperty $DstFile | Select-Object @{
                    l = 'Size'
                    e = {'({0:N2} MB)' -f $($_.Length / 1MB)
                    
                    
                    
                    
                    
                    }
                } | Select-Object -ExpandProperty Size) успешно выполнено"
                #Write-Output $true
            }
            catch
            {
                Write-Warning "Ошибка создания ахрива из файла`n`n$_`n`nSource = $Source`nSourceSize = $SourceSize`nDestinationFile = $DstFile`nCompressionLevel = $CompressionLevel`nOverwrite = $(if ($Overwrite)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nRemove = $(if ($Remove)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                    
                    
                    
                    
                    
                    })`nIncludeBaseDirectory = $(if ($IncludeBaseDirectory)
                    
                    
                    
                    
                    
                    {$true
                    
                    
                    
                    
                    
                    }else
                    
                    
                    
                    
                    
                    {$false
                
                
                
                
                
                })"
            }
        }
        if ($Remove)
        {
            try
            {
                Remove-Item -Path $Source -Recurse -Force -Confirm:$false
                Write-Verbose "$Source успешно удален"
            }
            catch
            {
                Write-Warning "Ошибка удаления $Source`n$_"
            }
        }
    }#process
    END{}
}

function Export-ZipArchive 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0,
                HelpMessage = "Specify source folder that have to be archived, example: 'c:\mydata.",
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    $(Get-ItemProperty -Path $_ | Select-Object -ExpandProperty Extension) -eq '.zip'
        })] 
        [Alias('FromZip')]
        [Alias('Src')]
        [string]$SourceArchive,
        [Parameter(Mandatory = $false,Position = 1,
                HelpMessage = "Specify destination folder for creating archive file, example: 'c:\tmp",
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    Test-Path $_ -PathType 'Container' -IsValid
        })] 
        [Alias('To')]
        [Alias('Dst')]
        [string]$Destination
    )
    BEGIN
    {
        try
        {
            Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
            Write-Verbose "Загружена сборка 'System.IO.Compression.FileSystem'"
        }
        catch
        {
            Write-Warning "Не удалось загрузить сборку 'System.IO.Compression.FileSystem'"
        }
    }#begin
    PROCESS
    {
        try
        {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($SourceArchive, $Destination)
            Write-Verbose "Архив $SourceArchive успешно распакован в $Destination"
            #Write-Output $true
        }
        catch
        {
            Write-Warning "Ошибка распаковки ахрива`n`n$_`n`nSourceArchive  = $SourceArchive`Destination = $Destination"
        }
    }#process
    END{}
}

function Convert-RGBToHex 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 0)][int]$Red,
        [Parameter(Mandatory = $true,Position = 1)][int]$Green,
        [Parameter(Mandatory = $true,Position = 2)][int]$Blue
    )
    $R = '{0:x}' -f $Red
    if ($R.Length -eq 1)
    {
        [string]$R += 0
    }
    $G = '{0:x}' -f $Green
    if ($G.Length -eq 1)
    {
        [string]$G += 0
    }
    $b = '{0:x}' -f $Blue
    if ($b.Length -eq 1)
    {
        [string]$b += 0
    }
    Write-Output "#$($R)$($G)$($b)"
}

function Get-SQLServerTableColumnsInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()][String]$TableName,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT 
    c.name 'Column Name',
    t.Name 'Data type',
    c.max_length 'Max Length',
    c.precision ,
    c.scale ,
    c.is_nullable,
    ISNULL(i.is_primary_key, 0) 'Primary Key'
FROM    
    sys.columns c
INNER JOIN 
    sys.types t ON c.user_type_id = t.user_type_id
LEFT OUTER JOIN 
    sys.index_columns ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
LEFT OUTER JOIN 
    sys.indexes i ON ic.object_id = i.object_id AND ic.index_id = i.index_id
WHERE
    c.object_id = OBJECT_ID('{0}')
"@ -f $TableName
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerLocks 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT
request_session_id AS spid,
resource_type AS restype,
resource_database_id AS dbid,
resource_description AS res,
resource_associated_entity_id AS resid,
request_mode AS mode,
request_status AS status
FROM sys.dm_tran_locks;
"@
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerConnectionInfo 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [int[]]$Session_Id,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT
session_id AS spid,
connect_time,
last_read,
last_write,
most_recent_sql_handle
FROM sys.dm_exec_connections
"@
    if($Session_Id)
    {
        $command += "`nWHERE session_id IN($($Session_Id -join ','));"
    }
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SybaseDetailedConnectionInfo 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeCurrentSPID,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeMasterDB
    )
    $command = @"
select  
       db.dbid   
       ,db.name as databasename
       ,db.suid
       ,db.status as db_state
       ,db.status2 as db_status
       ,db.crdate
       ,db.dumptrdate
       ,convert(varchar(30),suser_name(sp.suid)) as loginname
       ,sp.spid
       ,sp.hostname
       ,sp.ipaddr
       ,sp.loggedindatetime
       ,sp.clientapplname
       ,sp.program_name
       ,sp.cmd
       ,sp.status as login_status
       ,cpu
       ,physical_io
       ,memusage
       ,blocked
       ,time_blocked
       ,linenum
       ,'kill ' + cast(sp.spid as nvarchar(10)) as killcmd
       from master..sysprocesses as sp
       join master..sysdatabases as db
       on sp.dbid = db.dbid
where db.name is not null
"@
    if ($ExcludeCurrentSPID)
    {
        $command += "`nand sp.spid != @@SPID"
    }
    if ($ExcludeMasterDB)
    {
        $command += "`nand db.name != 'master'"
    }
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerConnectionNumber
{
    [CmdletBinding()]param(
        [Parameter(Mandatory = $false,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
    SELECT 
    DB_NAME(dbid) as DBName, 
    COUNT(dbid) as NumberOfConnections,
    loginame as LoginName
FROM
    sys.sysprocesses
WHERE 
    dbid > 0
GROUP BY 
    dbid, loginame
"@
    if($DatabaseName)
    {
        $command = $command -replace 'WHERE', ("WHERE DB_NAME(dbid) LIKE '%{0}%'" -f $DatabaseName)
    }
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerSessionInfo 
{
    [CmdletBinding()]param(
        [Parameter(Mandatory = $false,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [int[]]$Session_Id,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT
session_id AS spid,
login_time,
host_name,
program_name,
login_name,
nt_user_name,
last_request_start_time,
last_request_end_time
FROM sys.dm_exec_sessions
"@
    if($Session_Id)
    {
        $command += "`nWHERE session_id IN($($Session_Id -join ','));"
    }
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerBlocking 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT
session_id AS spid,
blocking_session_id,
command,
sql_handle,
database_id,
wait_type,
wait_time,
wait_resource
FROM sys.dm_exec_requests
WHERE blocking_session_id > 0;
"@
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerTextBlockingChain 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [int[]]$Session_Id,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT session_id, text
FROM sys.dm_exec_connections
CROSS APPLY sys.dm_exec_sql_text(most_recent_sql_handle) AS ST
"@
    if($Session_Id)
    {
        $command += "`nWHERE session_id IN($($Session_Id -join ','));"
    }
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-SQLServerForeingKey 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
                Position = 0,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,

        [Parameter(Mandatory = $false)]
        [switch]$AsPSObject
    )
    $command = @"
SELECT OBJECT_NAME(fkeyid) AS ForeingKeyTable,*
FROM sys.sysforeignkeys
WHERE rkeyid = OBJECT_ID('$($TableName)')
"@
    if ($AsPSObject)
    {
        $object = New-Object psobject -Property @{
            'Query' = $command
        }
        Write-Output $object
    }
    else
    {
        Write-Output $command
    }
}

function Get-OBDMemorial 
{
    <#
            пример 1
            #Get-OBDMemorial -Фамилия Измай -Имя Фели -Отчество Адо -ВариантыПоиска С_Начала_Поля -Verbose | ft -Wrap -AutoSize

            пример 2
            #Get-OBDMemorial -Фамилия Храмшин -МестоРождения 'Орловская обл' -ВариантыПоиска Полнотекстовый  -Verbose | ft -Wrap -AutoSize

            пример 3
            Get-OBDMemorial -Фамилия Яшин `
            -ДатаРождения 1925 `
            -ВариантыПоиска Полнотекстовый `
            -OutputFolder 'c:\MyReports' `
            -Format csv `
            -TimeOut 3500 `
            -CustomFileName MyTest `
            -InvokeOnCompletion `
            -Verbose


            пример 4

            $Results = Get-OBD-Memorial -Фамилия Иванов -ВариантыПоиска Полнотекстовый -Verbose
            $Results| Out-GridView -Title "Found $($Results.Count) records"

    #>

    [CmdletBinding()]

    Param(
        [Parameter(Mandatory = $true,Position = 0)][ValidatePattern('[а-яА-Я]')][String]$Фамилия,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$Имя,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$Отчество,
        [Parameter(Mandatory = $false)][ValidatePattern('[a-zA-Z]')][String]$ФамилияНаЛатинице,
        [Parameter(Mandatory = $false)][int]$ДатаРождения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$МестоРождения,
        [Parameter(Mandatory = $false)][String]$Дата_и_МестоПризыва,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$ПоследнееМестоСлужбы,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$ВоинскоеЗвание,
        [Parameter(Mandatory = $false)][String]$ЛагерныйНомер,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$ВоинскаяДолжность,
        [Parameter(Mandatory = $false)][int]$ДатаВыбытия,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$СтранаЗахоронения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$РегионЗахоронения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$МестоЗахоронения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$МестоВыбытия,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$Госпиталь,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$ОткудаПерезахоронен,
        [Parameter(Mandatory = $false)][String]$ДополнительнаяИнформация,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$ПервичноеМестоЗахоронения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$МестоПленения,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$Лагерь,
        [Parameter(Mandatory = $false)][int]$ДатаСмерти,
        [Parameter(Mandatory = $false)][int]$Номер,
        [Parameter(Mandatory = $false)][int]$Дата,
        [Parameter(Mandatory = $false)][ValidatePattern('[а-яА-Я]')][String]$МестоСоставленияПротокола,
        [Parameter(Mandatory = $false)][int]$Timeout = 3000,#с меньшим у меня переодически не успевали загружаться некоторые сраницы, не могу точно сказать из-за чего, толи комп, толи инет, толи сам сайт.
        [Parameter(Mandatory = $false)][string]$OutputFolder = "$env:SystemDrive\",
        [Parameter(Mandatory = $false)][string]$CustomFileName,
        [Parameter(Mandatory = $false)][ValidateSet('csv','txt','console')][string]$Format = 'console',
        [Parameter(Mandatory = $false)][switch]$InvokeOnCompletion,
        [Parameter(Mandatory = $false)][ValidateSet('С_Начала_Поля','Полнотекстовый')][string]$ВариантыПоиска = 'С_Начала_Поля',
        [Parameter(Mandatory = $false)][ValidateSet('Default','Unicode','UTF8')][Alias('Encode')][String]$CodePage = 'Default'
    )

    BEGIN
    {
        switch ($ВариантыПоиска)
        {
            'С_Начала_Поля'
            {
                $SearchOption = '=L~'
                break
            }
            'Полнотекстовый'
            {
                $SearchOption = '=T~'
                break
            }
        } #switch
            
        $LinkBase = "http://obd-memorial.ru/html/search.htm?f$SearchOption$Фамилия"
        if($Имя)
        {
            $LinkBase += "&n$SearchOption$Имя"
        }
        if($Отчество)
        {
            $LinkBase += "&s$SearchOption$Отчество"
        }
        if($ФамилияНаЛатинице)
        {
            $LinkBase += "&latname$SearchOption$ФамилияНаЛатинице"
        }
        if($ДатаРождения)
        {
            $LinkBase += "&bd$SearchOption$ДатаРождения"
        }
        if($МестоРождения)
        {
            $LinkBase += "&pb$SearchOption$МестоРождения"
        }
        if($Дата_и_МестоПризыва)
        {
            $LinkBase += "&d$SearchOption$Дата_и_МестоПризыва"
        }
        if($ПоследнееМестоСлужбы)
        {
            $LinkBase += "&lp$SearchOption$ПоследнееМестоСлужбы"
        }
        if($ВоинскоеЗвание)
        {
            $LinkBase += "&r$SearchOption$ВоинскоеЗвание"
        }
        if($ЛагерныйНомер)
        {
            $LinkBase += "&lagnum$SearchOption$ЛагерныйНомер"
        }
        if($ВоинскоеЗвание)
        {
            $LinkBase += "&post$SearchOption$ВоинскоеЗвание"
        }
        if($ДатаВыбытия)
        {
            $LinkBase += "&dateout$SearchOption$ДатаВыбытия"
        }
        if($СтранаЗахоронения)
        {
            $LinkBase += "&country$SearchOption$СтранаЗахоронения"
        }
        if($РегионЗахоронения)
        {
            $LinkBase += "&region$SearchOption$РегионЗахоронения"
        }
        if($МестоЗахоронения)
        {
            $LinkBase += "&place$SearchOption$МестоЗахоронения"
        }
        if($МестоВыбытия)
        {
            $LinkBase += "&placeout$SearchOption$МестоВыбытия"
        }
        if($Госпиталь)
        {
            $LinkBase += "&hosp$SearchOption$Госпиталь"
        }
        if($ОткудаПерезахоронен)
        {
            $LinkBase += "&from$SearchOption$ОткудаПерезахоронен"
        }
        if($ДополнительнаяИнформация)
        {
            $LinkBase += "&add$SearchOption$ДополнительнаяИнформация"
        }
        if($ПервичноеМестоЗахоронения)
        {
            $LinkBase += "&grave$SearchOption$ПервичноеМестоЗахоронения"
        }
        if($МестоПленения)
        {
            $LinkBase += "&capt$SearchOption$МестоПленения"
        }
        if($Лагерь)
        {
            $LinkBase += "&camp$SearchOption$Лагерь"
        }
        if($ДатаСмерти)
        {
            $LinkBase += "&dd$SearchOption$ДатаСмерти"
        }
        if($Номер)
        {
            $LinkBase += "&numreport$SearchOption$Номер"
        }
        if($Дата)
        {
            $LinkBase += "&datareport$SearchOption$Дата"
        }
        if($МестоСоставленияПротокола)
        {
            $LinkBase += "&placeprot$SearchOption$МестоСоставленияПротокола"
        }
        $LinkBase += '&entity=101111111111111&entities=32,9,18,26,25,24,28,27,23,34,22,20,21,19&ps=100'

        $ie_init = New-Object -ComObject InternetExplorer.Application
        if ($VisibleIE){ $ie_init.Visible = $true }
        $ie_init.Navigate("$LinkBase&p=1")
        while($ie_init.ReadyState -ne 4) 
        {
            Start-Sleep -Milliseconds $Timeout
        }
        $doc_init = $ie_init.Document
        $pages = @()

        if(($doc_init.getElementById('pages_top').innerText -replace'.*из |>>>') -ne $null)
        {
            [int]$pages = ($doc_init.getElementById('pages_top').innerText -replace '.*из |>>>')
        } #if
        else
        {
            $pages = 0
        } #else
        Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Found $pages pages of data total"
        if($pages -gt 20)
        {
            $Timeout += 3000
        }
        $counter = 1
        $globalarray = @()
        $ie_init.Quit()
    } #begin
    PROCESS
    {
        if ($pages -ge 1)
        {
            $counter..$pages | ForEach-Object {
                Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Getting data $counter/$pages"
                Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Source address $LinkBase&ps=100&p=$counter"
                $Tracker = New-TimeSpan -Seconds $(($Timeout / 1000)*($pages-($counter-1)))
                Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Estimated time $($Tracker.Hours) hours $($Tracker.Minutes) minutes $($Tracker.Seconds) seconds left"
                do
                {
                    $ie = New-Object -ComObject InternetExplorer.Application
                    $ie.Navigate("$LinkBase&p=$counter")
                    
                    while($ie.ReadyState -ne 4)
                    {
                        Start-Sleep -Milliseconds $Timeout
                    } #while
                    $doc = $ie.Document
                    $filter = (($doc.getElementById('resultTab')).innerHTML -split'showFullInfo')
                    $set = @()
                    1..($filter.Count-1) | ForEach-Object {
                        $set += $filter[$_]
                    }
                    $array = foreach($person in $set)
                    {
                        foreach($Info in $($person-split';'))
                        {
                            $Info-replace'</td><td style="font-size: 13px|" class="fio">|</td></tr></tbody>|">|[)]|[(]|</td></tr><tr onclick=.*'
                        } #foreach
                    } #foreach
                    $Result = for($i = 0;$i -lt $array.Count;$i += 8)
                    {
                        New-Object -TypeName PsObject -Property @{
                            'ID'           = $array[$i]-as[int]
                            '№'            = $array[$i+2]-as[int]
                            'ФИО'          = $array[$i+4]
                            'Дата рождения' = $array[$i+5]
                            'Дата выбытия' = $array[$i+6]
                            'Место рождения' = $array[$i+7]
                            'PageNum'      = $counter
                        } #psobject
                    } #for
                    if ($($Result[0].PageNum) -ne $counter)
                    {
                        $Timeout += 1000
                        Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Could not receive page, increasing timeout to $Timeout and trying again"
                    }#if
                } #do
                until ($($Result[0].PageNum) -eq $counter)

                $counter++
                foreach($piece in $Result)
                {
                    $globalarray += $piece
                } #foreach
                $ie.Quit()
            } #%
        } #if
    } #process
    END
    {
        if($pages -ge 1)
        {
            $globalarray = $globalarray |
            Where-Object{
                $_.Id -ne 0 -and $_.'№' -ne 0
            }|
            Select-Object '№', 'ID', 'ФИО', 'Дата рождения', 'Дата выбытия', 'Место рождения', 'PageNum' |
            Sort-Object '№', 'PageNum' -Unique
            Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Completed"
            if($OutputFolder)
            {
                if (-not (Test-Path $OutputFolder))
                {
                    $null = New-Item -Path $OutputFolder -ItemType Directory -Force
                } #if
                $OutputFile = "$OutputFolder\$(Get-Date -Format 'ddMMyyyy-HHmmss')_$Фамилия"
                if ($CustomFileName)
                {
                    $OutputFile = "$OutputFolder\$CustomFileName"
                }
                switch($Format)
                {
                    'csv'
                    {
                        $globalarray|
                        Where-Object{
                            $_.ID -ne 0
                        }|
                        ConvertTo-Csv -NoTypeInformation|
                        Out-File -FilePath "$OutputFile.csv" -Encoding $CodePage -Force 
                        if ($InvokeOnCompletion)
                        {
                            Invoke-Item "$OutputFile.csv"
                        } #if
                        break
                    } #csv
                    'txt'
                    {
                        $globalarray|
                        Where-Object{
                            $_.ID -ne 0
                        }|
                        Out-File -FilePath "$OutputFile.txt" -Encoding $CodePage -Force 
                        if ($InvokeOnCompletion)
                        {
                            Invoke-Item "$OutputFile.txt"
                        } #if
                        break
                    } #txt
                    'console'
                    {
                        Write-Output $globalarray
                        break
                    } #console
                } #switch
            } #if
        } #if
        else
        {
            Write-Verbose "$(Get-Date -Format 'HH:mm:ss') No data to display"
            Write-Verbose "$(Get-Date -Format 'HH:mm:ss') Source address $LinkBase&ps=100&p=$counter"
            Write-Warning "$(Get-Date -Format 'HH:mm:ss') Either no data matches or service was unavailable"
        } #else
    } #end
}

function Get-GoogleTranslate 
{
    #Get-GoogleTranslate -String 'hello world' -TranslateFrom Автоопределение -TranslateTo Русский -Verbose
    #Get-GoogleTranslate car -Full
    #Get-GoogleTranslate -TranslateFrom Русский -TranslateTo Английский -String правило -Online
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][ValidateNotNull()]
        [String]$String,
        [Parameter(Mandatory = $false,Position = 1,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(
                'Автоопределение','Азербайджанский',
                'Албанский','Английский','Арабский','Армянский','Африкаанс','Баскский','Белорусский','Бенгальский','Бирманский','Болгарский','Боснийский',
                'Валлийский','Венгерский','Вьетнамский','Галисийский','Греческий','Грузинский','Гуджарати','Датский','Зулу','Иврит','Игбо','Идиш','Индонезийский',
                'Ирландский','Исландский','Испанский','Итальянский','Йоруба','Казахский','Каннада','Каталанский','Китайский','Корейский','Креольский (Гаити)','Кхмерский',
                'Лаосский','Латынь','Латышский','Литовский','Македонский','Малагасийский','Малайский','Малайялам','Мальтийский','Маори','Маратхи','Монгольский','Немецкий',
                'Непали','Нидерландский','Норвежский','Панджаби','Персидский','Польский','Португальский','Румынский','Русский','Себуанский','Сербский','Сесото','Сингальский',
                'Словацкий','Словенский','Сомали','Суахили','Суданский','Тагальский','Таджикский','Тайский','Тамильский','Телугу','Турецкий','Узбекский','Украинский','Урду',
        'Финский','Французский','Хауса','Хинди','Хмонг','Хорватский','Чева','Чешский','Шведский','Эсперанто','Эстонский','Яванский','Японский')]
        [String]$TranslateFrom = 'Автоопределение',
        [Parameter(Mandatory = $false,Position = 2,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(
                'Азербайджанский',
                'Албанский','Английский','Арабский','Армянский','Африкаанс','Баскский','Белорусский','Бенгальский','Бирманский','Болгарский','Боснийский',
                'Валлийский','Венгерский','Вьетнамский','Галисийский','Греческий','Грузинский','Гуджарати','Датский','Зулу','Иврит','Игбо','Идиш','Индонезийский',
                'Ирландский','Исландский','Испанский','Итальянский','Йоруба','Казахский','Каннада','Каталанский','Китайский','Корейский','Креольский (Гаити)','Кхмерский',
                'Лаосский','Латынь','Латышский','Литовский','Македонский','Малагасийский','Малайский','Малайялам','Мальтийский','Маори','Маратхи','Монгольский','Немецкий',
                'Непали','Нидерландский','Норвежский','Панджаби','Персидский','Польский','Португальский','Румынский','Русский','Себуанский','Сербский','Сесото','Сингальский',
                'Словацкий','Словенский','Сомали','Суахили','Суданский','Тагальский','Таджикский','Тайский','Тамильский','Телугу','Турецкий','Узбекский','Украинский','Урду',
        'Финский','Французский','Хауса','Хинди','Хмонг','Хорватский','Чева','Чешский','Шведский','Эсперанто','Эстонский','Яванский','Японский')]
        [String]$TranslateTo = 'Русский',
        [Parameter(Mandatory = $false)]
        [Switch]$Full,
        [Parameter(Mandatory = $false)]
        [Switch]$Output,
        [Parameter(Mandatory = $false)]
        [Switch]$Online
    )

    BEGIN{
        $LanguageTable = @(
            [pscustomobject]@{
                Language = 'Автоопределение'
                URL      = 'auto'
            }, [pscustomobject]@{
                Language = 'Азербайджанский'
                URL      = 'az'
            }, [pscustomobject]@{
                Language = 'Албанский'
                URL      = 'sq'
            }, [pscustomobject]@{
                Language = 'Английский'
                URL      = 'en'
            }
            [pscustomobject]@{
                Language = 'Арабский'
                URL      = 'ar'
            }, [pscustomobject]@{
                Language = 'Армянский'
                URL      = 'hy'
            }, [pscustomobject]@{
                Language = 'Африкаанс'
                URL      = 'af'
            }, [pscustomobject]@{
                Language = 'Баскский'
                URL      = 'eu'
            }
            [pscustomobject]@{
                Language = 'Белорусский'
                URL      = 'be'
            }, [pscustomobject]@{
                Language = 'Бенгальский'
                URL      = 'bn'
            }, [pscustomobject]@{
                Language = 'Бирманский'
                URL      = 'my'
            }, [pscustomobject]@{
                Language = 'Болгарский'
                URL      = 'bg'
            }
            [pscustomobject]@{
                Language = 'Боснийский'
                URL      = 'bs'
            }, [pscustomobject]@{
                Language = 'Валийский'
                URL      = 'cy'
            }, [pscustomobject]@{
                Language = 'Венгерский'
                URL      = 'hu'
            }, [pscustomobject]@{
                Language = 'Вьетнамский'
                URL      = 'vi'
            }
            [pscustomobject]@{
                Language = 'Галийский'
                URL      = 'gl'
            }, [pscustomobject]@{
                Language = 'Греческий'
                URL      = 'el'
            }, [pscustomobject]@{
                Language = 'Грузинский'
                URL      = 'ka'
            }, [pscustomobject]@{
                Language = 'Гуджарати'
                URL      = 'gu'
            }
            [pscustomobject]@{
                Language = 'Датский'
                URL      = 'da'
            }, [pscustomobject]@{
                Language = 'Зулу'
                URL      = 'zu'
            }, [pscustomobject]@{
                Language = 'Иврит'
                URL      = 'iw'
            }, [pscustomobject]@{
                Language = 'Игбо'
                URL      = 'ig'
            }
            [pscustomobject]@{
                Language = 'Идиш'
                URL      = 'yi'
            }, [pscustomobject]@{
                Language = 'Индонезийский'
                URL      = 'id'
            }, [pscustomobject]@{
                Language = 'Исландский'
                URL      = 'is'
            }, [pscustomobject]@{
                Language = 'Испанский'
                URL      = 'es'
            }
            [pscustomobject]@{
                Language = 'Итальянский'
                URL      = 'it'
            }, [pscustomobject]@{
                Language = 'Йоруба'
                URL      = 'yo'
            }, [pscustomobject]@{
                Language = 'Казахский'
                URL      = 'kk'
            }, [pscustomobject]@{
                Language = 'Каннада'
                URL      = 'kn'
            }
            [pscustomobject]@{
                Language = 'Каталанский'
                URL      = 'ca'
            }, [pscustomobject]@{
                Language = 'Китайский'
                URL      = 'zh-CN'
            }, [pscustomobject]@{
                Language = 'Корейский'
                URL      = 'ko'
            }, [pscustomobject]@{
                Language = 'Креольский (Гаити)'
                URL      = 'ht'
            }
            [pscustomobject]@{
                Language = 'Кхмерский'
                URL      = 'km'
            }, [pscustomobject]@{
                Language = 'Лаосский'
                URL      = 'lo'
            }, [pscustomobject]@{
                Language = 'Латынь'
                URL      = 'la'
            }, [pscustomobject]@{
                Language = 'Латышский'
                URL      = 'lv'
            }
            [pscustomobject]@{
                Language = 'Литовский'
                URL      = 'lt'
            }, [pscustomobject]@{
                Language = 'Македонский'
                URL      = 'mk'
            }, [pscustomobject]@{
                Language = 'Малагасийский'
                URL      = 'mg'
            }, [pscustomobject]@{
                Language = 'Малайский'
                URL      = 'ms'
            }
            [pscustomobject]@{
                Language = 'Малайялам'
                URL      = 'ml'
            }, [pscustomobject]@{
                Language = 'Мальтийский'
                URL      = 'mt'
            }, [pscustomobject]@{
                Language = 'Маори'
                URL      = 'mi'
            }, [pscustomobject]@{
                Language = 'Маратхи'
                URL      = 'mr'
            }
            [pscustomobject]@{
                Language = 'Монгольский'
                URL      = 'mn'
            }, [pscustomobject]@{
                Language = 'Немецкий'
                URL      = 'de'
            }, [pscustomobject]@{
                Language = 'Непали'
                URL      = 'ne'
            }, [pscustomobject]@{
                Language = 'Нидерландский'
                URL      = 'nl'
            }
            [pscustomobject]@{
                Language = 'Норвежский'
                URL      = 'no'
            }, [pscustomobject]@{
                Language = 'Панджаби'
                URL      = 'pa'
            }, [pscustomobject]@{
                Language = 'Персидский'
                URL      = 'fa'
            }, [pscustomobject]@{
                Language = 'Польский'
                URL      = 'pl'
            }
            [pscustomobject]@{
                Language = 'Португальский'
                URL      = 'pt'
            }, [pscustomobject]@{
                Language = 'Румынский'
                URL      = 'ro'
            }, [pscustomobject]@{
                Language = 'Русский'
                URL      = 'ru'
            }, [pscustomobject]@{
                Language = 'Себуанский'
                URL      = 'ceb'
            }
            [pscustomobject]@{
                Language = 'Сербский'
                URL      = 'sr'
            }, [pscustomobject]@{
                Language = 'Сесото'
                URL      = 'st'
            }, [pscustomobject]@{
                Language = 'Сингальский'
                URL      = 'si'
            }, [pscustomobject]@{
                Language = 'Словацкий'
                URL      = 'sk'
            }
            [pscustomobject]@{
                Language = 'Словенский'
                URL      = 'sl'
            }, [pscustomobject]@{
                Language = 'Сомали'
                URL      = 'so'
            }, [pscustomobject]@{
                Language = 'Суахили'
                URL      = 'sw'
            }, [pscustomobject]@{
                Language = 'Суданский'
                URL      = 'su'
            }
            [pscustomobject]@{
                Language = 'Тагальский'
                URL      = 'tl'
            }, [pscustomobject]@{
                Language = 'Таджикский'
                URL      = 'tg'
            }, [pscustomobject]@{
                Language = 'Тайский'
                URL      = 'th'
            }, [pscustomobject]@{
                Language = 'Тамильский'
                URL      = 'ta'
            }
            [pscustomobject]@{
                Language = 'Телугу'
                URL      = 'te'
            }, [pscustomobject]@{
                Language = 'Турецкий'
                URL      = 'tr'
            }, [pscustomobject]@{
                Language = 'Узбекский'
                URL      = 'uz'
            }, [pscustomobject]@{
                Language = 'Украинский'
                URL      = 'uk'
            }
            [pscustomobject]@{
                Language = 'Урду'
                URL      = 'uk'
            }, [pscustomobject]@{
                Language = 'Финский'
                URL      = 'fi'
            }, [pscustomobject]@{
                Language = 'Французский'
                URL      = 'fr'
            }, [pscustomobject]@{
                Language = 'Хауса'
                URL      = 'ha'
            }
            [pscustomobject]@{
                Language = 'Хинди'
                URL      = 'hi'
            }, [pscustomobject]@{
                Language = 'Хмонг'
                URL      = 'hmn'
            }, [pscustomobject]@{
                Language = 'Хорватский'
                URL      = 'hr'
            }, [pscustomobject]@{
                Language = 'Чева'
                URL      = 'ny'
            }
            [pscustomobject]@{
                Language = 'Чешский'
                URL      = 'cs'
            }, [pscustomobject]@{
                Language = 'Шведский'
                URL      = 'sv'
            }, [pscustomobject]@{
                Language = 'Эсперанто'
                URL      = 'eo'
            }, [pscustomobject]@{
                Language = 'Эстонский'
                URL      = 'et'
            }
            [pscustomobject]@{
                Language = 'Яванский'
                URL      = 'jw'
            }, [pscustomobject]@{
                Language = 'Японский'
                URL      = 'ja'
        })
        $FromLang = $LanguageTable |
        Where-Object {
            $_.Language -eq $TranslateFrom
        } |
        Select-Object -ExpandProperty URL
        $ToLang = $LanguageTable |
        Where-Object {
            $_.Language -eq $TranslateTo
        } |
        Select-Object -ExpandProperty URL
    }
    PROCESS
    {
        if ($input -ne $null)
        {
            $Lookup = $input
        }
        $ie = New-Object -ComObject InternetExplorer.Application
        $ie.Navigate("https://translate.google.ru/#$FromLang/$ToLang/$String")
        if($Online)
        {
            $ie.Visible = $true
        }
        else
        {
            Write-Verbose "Using https://translate.google.ru/#$FromLang/$ToLang/$String"
            while ($ie.busy -eq $true) 
            {
                Start-Sleep -Milliseconds 300
            }
            $doc = $ie.Document
            $element = $doc.getElementById('result_box')
            if($FromLang -eq 'auto')
            {
                Write-Verbose "TranslateFrom=$((($doc.getElementById('gt-lang-src')).innerText.ToUpper().ToString() -Split "`n")[-1])"
            }
            if ($Output)
            {
                Write-Output $element.innerText.ToUpper()
            }
            else
            {
                Write-Host -BackgroundColor Black -ForegroundColor Green $element.innerText.ToUpper()
            }

            if (-not($Output))
            {
                if ($Full)
                {
                    $ExtraElement = $doc.getElementById('gt-lc')
                    if ($ExtraElement.innerText.IndexOf("$($Lookup): варианты перевода") -gt 0)
                    {
                        $ExtraResult = $ExtraElement.innerText.Remove(0,$($ExtraElement.innerText.IndexOf("$($String): варианты перевода"))) -Split "`n" | Where-Object {
                            $_ -match '\S+'
                        }
                        $Obj = @()
                        $Sorter = 1

                        for ($i = 0;$i -lt $ExtraResult.Count; $i++)
                        {
                            $SubObj = New-Object psobject
                            $SubObj | Add-Member -MemberType NoteProperty -Name Text -Value $ExtraResult[$i]
                            $SubObj | Add-Member -MemberType NoteProperty -Name Sorter -Value $Sorter
                            $Obj += $SubObj
                            if ($i%2 -ne 0)
                            {
                                $LineBreaker = New-Object psobject -Property @{
                                    'Text' = $null
                                    'Sorter' = $Sorter
                                }
                                $Obj += $LineBreaker
                                $Sorter++
                            }
                        }
                    }
                    if ($Obj.Count -gt 1)
                    {
                        Write-Host -BackgroundColor White -ForegroundColor Black "`n`n`n   ДОПОЛНИТЕЛЬНЫЕ ВАРИАНТЫ ПЕРЕВОДА   `n`n`n"
                        for ($ii = 0; $ii -lt $Obj.Count; $ii++)
                        {
                            if ($Obj[$ii].Sorter%2 -ne 0)
                            {
                                Write-Host -BackgroundColor Black -ForegroundColor White -Object $($Obj[$ii].Text)
                            }
                            else
                            {
                                Write-Host -BackgroundColor Black -ForegroundColor Cyan -Object $($Obj[$ii].Text)
                            }
                        }
                    }
                    else
                    {
                        Write-Host -BackgroundColor White -ForegroundColor Black '   ДОПОЛНИТЕЛЬНЫЕ ВАРИАНТЫ ПЕРЕВОДА НЕ НАЙДЕНЫ   '
                    }
                }
            }
        }
    }
    END
    {
        if(-not($Online))
        {
            $ie.Quit()
        }
    }
}

function Out-Speech 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $false)]
        [ValidateRange(-10,10)]
        [int]$SpeedRate = 0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0,100)]
        [int]$VolumeRate = 100,

        [Parameter(Mandatory = $false)]
        [switch]$GetVoices

    )
    $speechy = New-Object -ComObject SAPI.SPVoice
    $speechy.Volume = $VolumeRate
    $speechy.Rate = $SpeedRate
    if ($GetVoices)
    {
        $speechy.GetVoices() | % {Split-Path $_.Id -Leaf}
    }
    else
    {   
        [void]$speechy.Speak($Text)
    }
}

function Out-Log 
{
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
        [string]$Source = 'PK-Logs',

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
        [string]$ComputerName = $env:computername,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeOutputToConsole

    )
    BEGIN {
        if (-not(Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue))
        {
            New-EventLog -LogName $LogName -Source $Source
        }
    } #begin
    PROCESS {         
        if ($input -ne $null) 
        {
            $Message = $input
        }
        if ($IncludeOutputToConsole)
        {
            Write-Output $Message
        }  
        try 
        {
            Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -EventId $EventId -Message $Message -ComputerName $ComputerName -ErrorAction Stop
        }
        catch
        {
            Write-Warning "Ошибка записи в журнал $LogName`n$_"
        }
    } #process
    END {}
}

function Invoke-SQLServer 
{
    <#
            .SYNOPSIS
            Invokes query to Microsoft SQL Server.

            .DESCRIPTION
            Invokes query to Microsoft SQL Server.

            Author: Pashkov Kirill.

            .PARAMETER Query
            Define SQL/TSQL Query.

            .PARAMETER ExecuteNonQuery
            Uses ExecuteNonQuery method instead of ExecuteReader method. Use switch this to run objects such as procedures.

            .PARAMETER QueryTimeout
            Define command timeout. Set 0 for no timeout.

            .PARAMETER ServerName
            Target ServerName or IP address, default is set to localhost.

            .PARAMETER DefaultDatabase
            Target DefaultDatabase name, default is set to master.

            .PARAMETER IntegratedSecurity
            Identifies wheter use Integrated Windows Security or not, two options available 'True' for Integrated Security mode and 'False' for SQL Server Security mode.

            .PARAMETER Login
            Defines login name to connect database server using SQL Server Security mode.

            .PARAMETER Password
            Defines password to connect database server using SQL Server Security mode.

            .PARAMETER CustomConnectionString
            Defines desired connection string to connect to the SQL Server. I recommend http://www.connectionstrings.com/

            .EXAMPLE
            PS C:\> Invoke-SQLServer -Query 'SELECT @@VERSION' -IntegratedSecurity 'True'

            Column1                                                                                                                                                                  
            -------                                                                                                                                                                  
            Microsoft SQL Server 2012 - 11.0.2100.60 (Intel X86) ... 



            This command returns SQL Server version, while using Integrated Security mode.

            .EXAMPLE
            PS C:\> Invoke-SQLServer -Query "SELECT name FROM sys.databases WHERE name != N'master'" -IntegratedSecurity 'False' -Login login -Password password | Format-Table -AutoSize

            name                
            ----                
            AdventureWorks2012  
            AdventureWorksDW2012
            model               
            msdb                
            Northwind           
            pubs                   
            Sample              
            tempdb



            This command returns database list, while using local SQL Server Security mode.

            .EXAMPLE
            PS C:\> Invoke-SQLServer $(Get-SQLServerSessionInfo -Session_Id (10..15)) | Format-Table -Wrap -AutoSize

            spid login_time          host_name program_name login_name nt_user_name last_request_start_time last_request_end_time
            ---- ----------          --------- ------------ ---------- ------------ ----------------------- ---------------------
            10 02.07.2015 14:47:59                        sa                      02.07.2015 14:47:59                          
            11 02.07.2015 14:47:59                        sa                      02.07.2015 14:47:59                          
            12 02.07.2015 14:47:59                        sa                      02.07.2015 14:47:59                          
            13 02.07.2015 14:48:26                        sa                      02.07.2015 14:48:26                          
            14 02.07.2015 14:48:25                        sa                      02.07.2015 14:48:25                          
            15 03.07.2015 15:58:17                        sa                      03.07.2015 15:58:17         

            This command uses helper function Get-SQLServerSessionInfo to run pre defined query to check session information.        

            .LINK

            Mail me to KirillPashkov@yandex.ru for feedback!
    #>
    [CmdletBinding()]
    [OutputType([System.Data.DataTable])]
    param (
        [Parameter(Mandatory = $true,
                Position = 0,
                HelpMessage = 'Type SQL\TSQL query to execute.',
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('Script')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Type SQL Server computername or IP address.')]
        [Alias('ComputerName')]
        [string]$ServerName = $env:computername,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Type SQL Server default database name.')]
        [Alias('Base')]
        [string]$DefaultDatabase = 'master',

        [Parameter(Mandatory = $false)]
        [ValidateSet('True','False')]
        [string]$IntegratedSecurity = 'True',

        [Parameter(Mandatory = $false)]
        [Alias('UserName')]
        [string]$Login,

        [Parameter(Mandatory = $false)]
        [Alias('Pwd')]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [Alias('Timeout')]
        [int]$QueryTimeout = 30,

        [Parameter(Mandatory = $false)]
        [string]$CustomConnectionString,

        [Parameter(Mandatory = $false)]
        [switch]$ExecuteNonQuery

    )
    BEGIN
    {
        if ($CustomConnectionString)
        {
            $ConnectionStrig = $CustomConnectionString
        }
        else
        {
            switch ($IntegratedSecurity){
                'True' 
                {
                    $ConnectionStrig = "Server=$ServerName;Database=$DefaultDatabase;Integrated Security=$IntegratedSecurity;"
                    break
                }
                'False'
                {
                    $ConnectionStrig = "Server=$ServerName;Database=$DefaultDatabase;uid=$Login; pwd=$Password;Integrated Security=$IntegratedSecurity;"
                    break
                }
            }
        }
        $object = New-Object System.Data.SqlClient.SqlConnection
        $Table = New-Object System.Data.DataTable
        $object.ConnectionString = $ConnectionStrig
        try 
        {
            $object.Open()
        }
        catch
        {
            Write-Warning "Failed to open new connection. Using $ConnectionStrig as connection string."
            break
        }
    }
    PROCESS
    {
        $command = $object.CreateCommand()
        $command.CommandTimeout = $QueryTimeout
        $command.CommandText = $Query

        if (-not($ExecuteNonQuery))
        {
            $Table.Load($command.ExecuteReader())
            Write-Output $Table
        }
        else
        {
            try
            {
                $command.ExecuteNonQuery()
                $true
            }
            catch [Exception]
            {
                throw $_
            }
        }
            
    }
    END
    {
        $command.Connection.Close()
        $command.Dispose()
        $Table.Dispose()
    }
}

function Get-DiskSpaceInfo 
{
    <#
            .SYNOPSIS
            Gets logical disk information.

            .DESCRIPTION
            Gets logical disk information using WMI.

            Author: Pashkov Kirill.

            .PARAMETER DriveType
            Specify target computer disk drive type, choose one of available - Floppy, Local, Opical.

            .PARAMETER Credentials
            Specify Credentials to use differnt credentials.

            .EXAMPLE
            Get-DiskSpaceInfo -ComputerName localhost

            Drive        : C:
            Size         : 465,76
            FreeSpace    : 362,89
            FreePercent  : 77,91
            ComputerName : MyComputer1

            .EXAMPLE
            Get-DiskSpaceInfo -ComputerName remotepc -Credentials remotepc\admin

            Drive        : C:
            Size         : 465,76
            FreeSpace    : 362,89
            FreePercent  : 77,91
            ComputerName : remotepc

            .EXAMPLE
            Get-Content C:\comps.txt | Get-DiskSpaceInfo | Format-Table -AutoSize

            Drive Size   FreeSpace FreePercent ComputerName   
            ----- ----   --------- ----------- ------------   
            C:    465,76 362,89    77,91       MyComputer1
            C:    465,76 362,89    77,91       MyComputer2
            C:    465,76 362,89    77,91       MyComputer3
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                Position = 1,
                HelpMessage = 'Computer name or IP Address',
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineName')]
        [string[]]$ComputerName = 'localhost',

        [Parameter(Position = 2,
        ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Floppy','Local','Opical')]
        [string]$DriveType = 'Local',

        [Parameter(Mandatory = $false)]
        [string]$Credential

    )
    BEGIN{
        if ($Credential)
        {
            [PSCredential]$CustomCredentials = (Get-Credential -Credential $Credential)
        }
    }
    PROCESS{
        foreach ($Computer in $ComputerName)
        {
            if (Test-Connection $Computer -Quiet -Count 1)
            {
                $params = @{
                    'ComputerName' = $Computer
                    'Class'      = 'Win32_LogicalDisk'
                }

                switch ($DriveType){
                    'Local' 
                    {
                        $params.Add('Filter','DriveType=3')
                        break
                    }
                    'Floppy' 
                    {
                        $params.Add('Filter', 'DriveType=2')
                        break
                    }
                    'Optical' 
                    {
                        $params.Add('Filter', 'DriveType=5')
                        break
                    }
                }

                if ($Credential)
                {
                    $params.Add('Credential',$CustomCredentials)
                }

                Get-WmiObject @params |
                Select-Object @{
                    Name       = 'Drive'
                    Expression = {
                        $_.DeviceID
                    }
                }, 
                @{
                    Name       = 'Size'
                    Expression = {
                        '{0:N2}' -f ($_.Size / 1GB)
                    }
                }, 
                @{
                    Name       = 'FreeSpace'
                    Expression = {
                        '{0:N2}' -f ($_.FreeSpace / 1GB)
                    }
                }, 
                @{
                    Name       = 'FreePercent'
                    Expression = {
                        '{0:N2}' -f ($_.FreeSpace / $_.Size * 100)
                    }
                }, 
                @{
                    Name       = 'ComputerName'
                    Expression = {
                        $_.PSComputerName
                    }
                }
                Write-Verbose "Информация для $Computer успешно получена.`n"
            }
            else
            {
                Write-Verbose "$Computer не доступен."
            }
        }
    }
    END{}
}

function Get-SystemInfo 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        [Parameter(Mandatory = $false)]
        [string]$Credential


    )
    BEGIN{
        if ($Credential)
        {
            [PSCredential]$CustomCredentials = (Get-Credential -Credential $Credential)
        }
        $objarray = @()

    }
    PROCESS{
        foreach ($Computer in $ComputerName)
        {
            if (Test-Connection $Computer -Quiet -Count 1)
            {
                $params = @{
                    'ComputerName' = $Computer
                }
                if ($Credential)
                {
                    $params.Add('Credential',$CustomCredentials)
                }
                $cs = Get-WmiObject -Class win32_computersystem @params
                $os = Get-WmiObject -Class win32_operatingsystem @params
                $bios = Get-WmiObject -Class win32_bios @params
                $cpu = Get-WmiObject -Class win32_processor @params

                $properties = @{
                    'Manufacturer'  = $cs.Manufacturer
                    'Model'         = $cs.Model
                    'RAM(MB)'       = $cs.TotalPhysicalMemory / 1MB -as [int]
                    'NumberOfLogicalProcessors' = $cpu.NumberOfLogicalProcessors
                    'BIOSSerial'    = $bios.SerialNumber
                    'BIOSVersion'   = $bios.Version
                    'BIOSReleaseDate' = $bios.ConvertToDateTime($bios.ReleaseDate)
                    'ComputerName'  = $os.__SERVER
                    'OSName'        = $os.Caption
                    'OSArchitecture' = $os.OSArchitecture
                    'OSBuild'       = $os.BuildNumber
                    'OSVersion'     = $os.Version
                    'SPVersion'     = $os.ServicePackMajorVersion
                    'LastBootUpTime' = $os.ConvertToDateTime($os.LastBootUpTime)
                    'InstallDate'   = $os.ConvertToDateTime($os.InstallDate)
                }
                
                $Select = "Manufacturer,Model,BIOSSerial,BIOSVersion,BIOSReleaseDate,'RAM(MB)',"
                $cpunum = 0
                $cpu | % {
                    $properties.Add("CPU$($cpunum)_Maxclockspeed",$_.maxclockspeed)
                    $Select += "CPU$($cpunum)_Maxclockspeed,"
                    $properties.Add("CPU$($cpunum)_AddressWidth",$_.addressWidth)
                    $Select += "CPU$($cpunum)_AddressWidth,"
                    $properties.Add("CPU$($cpunum)_NumberOfCores",$_.numberOfCores)
                    $Select += "CPU$($cpunum)_NumberOfCores,"
                    $cpunum++
                }
                $Select += 'ComputerName,OSName,OSArchitecture,OSBuild,OSVersion,SPVersion,InstallDate,LastBootUpTime'
                $Obj = New-Object -TypeName psobject -Property $properties 
                $objarray += $Obj
                Write-Verbose "Информация для $Computer успешно получена.`n"
            }
            else
            {
                Write-Verbose "$Computer не доступен."
            }
        }
                          
    }
    END{
        Write-Output $(Invoke-Expression ('$' + 'objarray | Select  ' + $Select))


    }
}

function Get-PortStatusInfo 
{
    <#
            .SYNOPSIS
            Gets TCP port connection state.

            .DESCRIPTION
            Gets TCP port connection state.

            Author: Pashkov Kirill.

            .PARAMETER Destination
            Specify target computer name or IP address.

            .PARAMETER Port
            Specify TCP port number to check.

            .PARAMETER Silent
            Specify Silent switch to run command silently.

            .EXAMPLE
            Get-PortStatusInfo -Destination remotepc -Port 3389 | Format-Table -AutoSize

            Destination Port Available
            ----------- ---- -----
            QUIK-TEST   3389  True

            .EXAMPLE
            Get-PortStatusInfo -Destination remotepc -Port 3389 | Format-Table -AutoSize

            Destination Port Available
            ----------- ---- -----
            QUIK-TEST   3389  True
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('ComputerName')]
        [string[]]$Destination,
        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [int[]]$Port,
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 3000,
        [Parameter(Mandatory = $false)]
        [switch]$Silent
    )
    BEGIN{
        $Output = @()
        if($Silent)
        {
            $ErrorActionPreference = 'SilentlyContinue'
        }
    }
    PROCESS{
        foreach ($Computer in $Destination)
        {
            Write-Verbose "Checking $Computer - started."
            foreach ($Single_Port in $Port)
            {
                Write-Verbose "$Computer port $Single_Port"
                $Network = New-Object Net.Sockets.TcpClient
                $wait = $Network.BeginConnect($Computer,$Single_Port,$null,$null)
                $Results = $wait.AsyncWaitHandle.WaitOne($Timeout,$false)
                $Results = $Network.Connected
                $object = New-Object System.Object
                $object|Add-Member -MemberType NoteProperty -Name Destination -Value $Computer
                $object|Add-Member -MemberType NoteProperty -Name Port -Value $Single_Port
                $object|Add-Member -MemberType NoteProperty -Name Available -Value $Results
                $Network.Close()
                $Network.Dispose()
                $Output += $object
                Write-Verbose "Status: $Results"
            }
            Write-Verbose "Checking $Computer - completed."
        }

    }
    END {
        Write-Output $Output
    }
}

function Invoke-SybaseASEQuery 
{
    <#
            .SYNOPSIS
            Executes Sybase ASE Query.

            .DESCRIPTION
            Executes Sybase ASE Query

            Author: Pashkov Kirill.

            .PARAMETER Query
            Define TSQL Query.

            .PARAMETER ServerName
            Target ServerName or IP address, default is set to localhost.

            .PARAMETER DefaultDatabase
            Target DefaultDatabase name, default is set to master.

            .PARAMETER Port
            Port

            .PARAMETER DSN
            DSN

            .PARAMETER Login
            Login

            .PARAMETER Password
            Password

            .PARAMETER Timeout
            Timeout

            .PARAMETER TableNumber
            TableNumber

            .EXAMPLE
            Invoke-SybaseASEQuery -ComputerName SRV-ASE01 -DSN SRV-ASE01 -Port 1234 -Login login -Password password -DefaultDatabase master -Query 'select * from syslogins' | Select -First 1 | ft -AutoSize

            suid status accdate                totcpu      totio spacelimit timelimit resultlimit dbname       name        
            ---- ------ -------                ------      ----- ---------- --------- ----------- ------       ----        
            1      0 03.10.2011 16:57:39   6029579  294517499          0         0           0 master       sa 



            This command returns data contained in syslogin table.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,Position = 1,
                HelpMessage = 'Type TSQL query to execute.',
                ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
        [Alias('Script')]
        [string]$Query,

        [Parameter(Mandatory = $true,HelpMessage = 'Type Sybase ASE DSN.')]
        [string]$DSN = 'localhost',

        [Parameter(Mandatory = $true,HelpMessage = 'Type Sybase ASE name or IP address')]
        [Alias('ComputerName')]
        [string]$ServerName,

        [Parameter(Mandatory = $true,HelpMessage = 'Type Sybase ASE address port')]
        [int]$Port,

        [Parameter(Mandatory = $true,HelpMessage = 'Type Sybase ASE default database name.')]
        [Alias('Base')]
        [string]$DefaultDatabase = 'master',

        [Parameter(Mandatory = $true)]
        [Alias('UserName')]
        [string]$Login,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 30,

        [Parameter(Mandatory = $false)]
        [int[]]$TableNumber = 0
    )
    BEGIN   {
        $Connection = New-Object System.Data.Odbc.OdbcConnection
        $Connection.ConnectionString = "driver={Adaptive Server Enterprise};dsn=$DSN;db=$DefaultDatabase;na=$ServerName,$Port;uid=$Login;pwd=$Password;"
        $Connection.Open()
    }
    PROCESS {
        Write-Verbose "Executing query:`n`n$Query`n"
        $command = New-Object System.Data.Odbc.OdbcCommand -ArgumentList ($Query, $Connection)
        $command.CommandTimeout = $Timeout
        $DataSet = New-Object System.Data.DataSet
        $DataAdapter = New-Object System.Data.Odbc.OdbcDataAdapter -ArgumentList ($command)
        $null = $DataAdapter.Fill($DataSet)
        
        $TableNumber | % {
        $CurrentItem = $_
            if ($DataSet.Tables[$CurrentItem])
            {
                $Result = $($DataSet.Tables[$CurrentItem])
                if ($Result -ne $null)
                {
                    Write-Verbose "TableNumber $CurrentItem"
                    Write-Output $($DataSet.Tables[$CurrentItem])
                }
            }
        }
    }
    END {
        $Connection.Close()
    }
}

function Get-ComputerReport 
{
    <#REQUIRES EnhancedHTML2 module installed.#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = $env:computername,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:temp\Reports",

        [Parameter(Mandatory = $false)]
        [ValidateSet('.html','.hta')]
        [string]$Format = '.html',

        [Parameter(Mandatory = $false)]
        [switch]$InvokeOnCompletion
    )
    BEGIN{
        if (!(Get-Module -Name EnhancedHTML2))
        {
            try
            {
                Import-Module EnhancedHTML2
            }
            catch
            {
                Write-Warning 'EnhancedHTML2 module is required'
                break
            }
        }
        if (Test-Path $OutputPath)
        {
            #exists 
        }
        else
        {
            $null = mkdir $OutputPath
        }
        $CSS = @"
<style>
body {
    font-family:Tahoma;
    font-size:10pt;
    background-color:white;
}

h2 {
    border-top:3px solid #666666;
}

th {
    font-weight:bold;
    color:#eeeeee;
    background-color:#333333;
    cursor:pointer;
}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
.paginate_enabled_next, .paginate_enabled_previous {
    cursor:pointer; 
    border:1px solid #222222; 
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.paginate_disabled_previous, .paginate_disabled_next {
    color:#666666; 
    cursor:pointer;
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.dataTables_info { margin-bottom:4px; }
.sectionheader { cursor:pointer; }
.sectionheader:hover { color:blue; }
.grid { width:100% }
.red {
    color:red;
    font-weight:bold;
} 
</style>
"@
    }
    PROCESS{
        foreach ($Computer in $ComputerName)
        {
            if (Test-Connection $ComputerName -Count 1 -Quiet) {
            $frag1 = Get-SystemInfo -ComputerName $Computer |
            <#Select-Object ComputerName, 
            Manufacturer, 
            Model, 
            'RAM(MB)', 
            BIOSSerial, 
            BIOSVersion, 
            BIOSReleaseDate, 
            OSName, 
            OSArchitecture, 
            OSBuild, 
            OSVersion, 
            SPVersion, 
            LastBootUpTime, 
            InstallDate |#>
            ConvertTo-EnhancedHTMLFragment -TableCssID SYSTABLE `
            -DivCssID SYSDIV `
            -DivCssClass SYSDIVCLASS `
            -TableCssClass SYSTABLECSSCLASS `
            -As List `
            -Properties * `
            -MakeHiddenSection `
            -PreContent '<h2>System Details</h2>' |
            Out-String

            $frag2 = Get-DiskSpaceInfo -ComputerName $Computer |
            ConvertTo-EnhancedHTMLFragment -TableCssID DISKTABLE `
            -DivCssID DISKDIV `
            -DivCssClass DISKDIVCLASS `
            -TableCssClass DISKTABLECSSCLASS `
            -As Table `
            -Properties * `
            -EvenRowCssClass 'even' `
            -OddRowCssClass 'odd' `
            -MakeHiddenSection `
            -PreContent '<h2>Disks</h2>' |
            Out-String

            $frag3 = Get-Process -ComputerName $Computer |
            ConvertTo-EnhancedHTMLFragment -TableCssID PROCTABLE `
            -DivCssID PROCDIV `
            -DivCssClass PROCDIVCLASS `
            -TableCssClass PROCTABLECSSCLASS `
            -As Table `
            -Properties Name, ID, VM, PM, WS, CPU `
            -EvenRowCssClass 'even' `
            -OddRowCssClass 'odd' `
            -MakeHiddenSection `
            -MakeTableDynamic `
            -PreContent '<h2>Processes</h2>' |
            Out-String
            $Path = Join-Path -Path $OutputPath -ChildPath "$Computer$Format"
            ConvertTo-EnhancedHTML -HTMLFragments $frag1, $frag2, $frag3 `
            -Title "System report for $Computer" `
            -PreContent "<h1>System report for $Computer</h1>" `
            -PostContent "<br /><br />Retreived $(Get-Date)" `
            -CssStyleSheet $CSS |
            Out-File $Path -Force
            Write-Verbose "Report file is created in $Path"
            }#test-connection
            else
            {
                Write-Warning "$Computer is unreachable"
            }
        }#foreach
    }#process
    END {
        if ($InvokeOnCompletion)
        {
            Invoke-Item $Path
        }
    }
}

function Get-ComputerUptime 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = 'localhost',
    
        [Parameter(Mandatory = $false)]
        [string]$Credential
    )
    BEGIN{
        if ($Credential)
        {
            [PSCredential]$CustomCredentials = (Get-Credential -Credential $Credential)
        }
        $objarray = @()
    }
    PROCESS{
        foreach ($Computer in $ComputerName)
        {
            $params = @{
                'ComputerName' = $Computer
            }
            if ($Credential)
            {
                $params.Add('Credential',$CustomCredentials)
            }
            $wmi = Get-WmiObject -Class Win32_OperatingSystem
            $bootup = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
            $span = New-TimeSpan -Start $bootup -End $(Get-Date)
            $Obj = New-Object PSObject
            Add-Member -InputObject $Obj -MemberType NoteProperty -Name ComputerName -Value $wmi.__SERVER
            Add-Member -InputObject $Obj -MemberType NoteProperty -Name Days -Value $span.Days
            Add-Member -InputObject $Obj -MemberType NoteProperty -Name Hours -Value $span.Hours
            Add-Member -InputObject $Obj -MemberType NoteProperty -Name Minutes -Value $span.Minutes
            Add-Member -InputObject $Obj -MemberType NoteProperty -Name Seconds -Value $span.Seconds
            $objarray += $Obj
        }
    
    }
    END{
        Write-Output $objarray
    }
}

function Show-Menu 
{
    [CmdletBinding()]
    Param()
    $Message = ''
    $Continue = $true    
    $Screen = $($host.UI.RawUI.WindowSize.Width)
    DO 
    {
        Clear-Host
        Write-Host "$('=' * $($Screen*0.99))"
        Write-Host "$('=' * $([Math]::Round($Screen*0.47))) MENU $('=' * $([Math]::Round($Screen * 0.46)))"
        Write-Host "$('=' * $($Screen*0.99))"
        Write-Host ''

        if ($Message -ne '')
        {
            Write-Host "$Message"
            Write-Host ''
        }

        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))1.`tGet system information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))2.`tGet disk space information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))3.`tGet port status information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))4.`tGet computer uptime information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))5.`tGet computer shutdown information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))6.`tGet host IP addresses information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))7.`tGet geolocation by IP address information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))8.`tGet current date detailed information."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))9.`tGet CBR rates."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))10.`tGet CBR bik DB."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))11.`tGet console Image from image file."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))12.`tUnzip archive file."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))13.`tConvert from Base64."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))14.`tConvert to Base64."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))15.`tExport archive file."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))16.`tImport archive file."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))17.`tGet CBR metal rates."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))18.`tGet google translate."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))19.`tConvert currencies."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))20.`tGet Powershell news."
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))21.`tSet wallpapper."
        Write-Host ''
        Write-Host "$(' '*$([Math]::Round($Screen*0.25)))Q.`tQuit menu."
        Write-Host ''

        $Message = ''
        $Choice = Read-Host "$(' '*$([Math]::Round($Screen*0.25)))Select option"
        $Colors = @{
            'BackgroundColor' = 'Black'
            'ForegroundColor' = 'White'
        }
        switch ($Choice){
            1 
            { 
                Clear-Host
                $Infos = Get-SystemInfo -Verbose
                foreach ($Info in $Infos)
                {
                    $Info |
                    Get-Member -MemberType NoteProperty |
                    Select-Object -ExpandProperty Name |
                    ForEach-Object {
                        Write-Host "$($_) : $($Info.$($_))" @Colors
                    }
                    Write-Host ''
                }
            }

            2 
            { 
                Clear-Host
                $Infos = Get-DiskSpaceInfo -Verbose
                foreach ($Info in $Infos)
                {
                    $Info |
                    Get-Member -MemberType NoteProperty |
                    Select-Object -ExpandProperty Name |
                    ForEach-Object {
                        Write-Host "$($_) : $($Info.$($_))" @Colors
                    }
                    Write-Host ''
                }
            }

            3 
            { 
                Clear-Host
                $Infos = Get-PortStatusInfo -Verbose
                foreach ($Info in $Infos)
                {
                    $Info |
                    Get-Member -MemberType NoteProperty |
                    Select-Object -ExpandProperty Name |
                    ForEach-Object {
                        Write-Host "$($_) : $($Info.$($_))" @Colors
                    }
                    Write-Host ''
                }
            }

            4 
            { 
                Clear-Host
                $Infos = Get-ComputerUptime
                foreach ($Info in $Infos)
                {
                    $Info |
                    Get-Member -MemberType NoteProperty |
                    Select-Object -ExpandProperty Name |
                    ForEach-Object {
                        Write-Host "$($_) : $($Info.$($_))" @Colors
                    }
                    Write-Host ''
                }
            }
            5 
            { 
                Clear-Host
                Get-ShutdownInfo | Format-Table -AutoSize
            }

            6 
            { 
                Clear-Host
                Get-HostAddresses
            }

            7 
            { 
                Clear-Host
                Get-GeoLocation
            }

            8  
            {
                Clear-Host
                Get-CurrentDateDetailedInfo
            }

            9 
            { 
                Clear-Host
                Get-CBRRates -Verbose | Format-Table -AutoSize
            }

            10 
            { 
                Clear-Host
                Get-CBRBikDB -Verbose
            }

            11 
            { 
                Clear-Host
                Invoke-ConsoleImage -IsGrayscale
            }

            111 
            { 
                Clear-Host
                Invoke-ConsoleImage
            }

            12 
            {
                Clear-Host
                Invoke-Unzip -Verbose
            }
            13 
            {
                Clear-Host
                ConvertFrom-Base64
            }
            14 
            {
                Clear-Host
                ConvertTo-Base64
            }
            15
            {
                Clear-Host
                Export-ZipArchive -Verbose
            }
            16
            {
                Clear-Host
                Import-ZipArchive -Verbose
            }
            17
            {
                Clear-Host
                Get-CBRMetallRates -Verbose
            }
            18
            {
                Clear-Host
                Get-GoogleTranslate -Verbose
            }
            19
            {
                Clear-Host
                Convert-ToRUB -Verbose
            }
            20
            {
                Clear-Host
                Get-PSNews
            }
            21
            {
                Clear-Host
                Set-Wallpaper -Style Stretch -Verbose
            }
            'Q' 
            {
                $Continue = $false
            }

            default 
            {
                $Message = 'Unknown choice, try again'
            }
        }
        if ($Continue)
        {
            Read-Host 'Hit any key to continue'
        }
        Clear-Host
    }
    WHILE ($Continue)
    Write-Host 'Exited menu. Have a nice day.'
}

function Invoke-MouseClick 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,Position = 1)]
        [ValidateSet('Left','Right','Middle')]
        [string]$Button,

        [Parameter(Mandatory = $false,Position = 2)]
        [int]$PositionX,

        [Parameter(Mandatory = $false,Position = 3)]
        [int]$PositionY
    )
    BEGIN 
    {
        $signature = @" 
      [DllImport("user32.dll",CharSet=CharSet.Auto, CallingConvention=CallingConvention.StdCall)]
      public static extern void mouse_event(long dwFlags, long dx, long dy, long cButtons, long dwExtraInfo);
"@ }
    PROCESS{
        $SendMouseClick = Add-Type -MemberDefinition $signature -Name 'Win32MouseEventNew' -Namespace Win32Functions -PassThru 
    
        if (($PositionX) -and ($PositionY))
        {
            [Windows.Forms.Cursor]::Position = (New-Object System.Drawing.Point -ArgumentList $PositionX, $PositionY)
        }

        switch ($Button){
            'Left'
            {
                $SendMouseClick::mouse_event(0x00000002, 0, 0, 0, 0)
                $SendMouseClick::mouse_event(0x00000004, 0, 0, 0, 0)
            }
            'Right'
            {
                $SendMouseClick::mouse_event(0x00000008, 0, 0, 0, 0)
                $SendMouseClick::mouse_event(0x00000010, 0, 0, 0, 0)
            }
            'Middle'
            {
                $SendMouseClick::mouse_event(0x00000020, 0, 0, 0, 0)
                $SendMouseClick::mouse_event(0x00000040, 0, 0, 0, 0)
            }
        }
    }
    END{}
}

function Get-ScreenInfo 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ScreenSize','MousePosition')]
        [string]$Show
    )
    switch ($Show) {
        'ScreenSize' 
        {
            [Windows.Forms.Cursor]::Clip | Select-Object Width, Height
        }
        'MousePosition' 
        {
            [Windows.Forms.Cursor]::Position | Select-Object X, Y
        }
    }
}

function Invoke-ConsoleImage 
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [switch]$IsGrayscale
    )

    $CharHeightWidthRatio = 2.2

    $null = [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

    function Get-PixelConsoleColor ([System.Drawing.Color]$Color) 
    {
        if ($Color.GetSaturation() -lt .2 -or $Color.GetBrightness() -gt .9 -or
        $Color.GetBrightness() -lt .1) 
        {
            return [ConsoleColor]::White
        }
        switch ($Color.GetHue()) {
            {
                $_ -ge 330 -or $_ -lt 16
            } 
            {
                return [ConsoleColor]::Red
            }
            {
                $_ -ge 16 -and $_ -lt 90
            } 
            {
                return [ConsoleColor]::Yellow
            }
            {
                $_ -ge 90 -and $_ -lt 160
            } 
            {
                return [ConsoleColor]::Green
            }
            {
                $_ -ge 160 -and $_ -lt 210
            } 
            {
                return [ConsoleColor]::Cyan
            }
            {
                $_ -ge 210 -and $_ -lt 270
            } 
            {
                return [ConsoleColor]::Blue
            }
            {
                $_ -ge 270 -and $_ -lt 330
            } 
            {
                return [ConsoleColor]::Magenta
            }
        }
    }

    function Get-PixelChar ([Drawing.Color]$Color) 
    {
        $chars = ' .,:;+iIH$@'
        $brightness = [math]::Floor($Color.GetBrightness() * $chars.Length)
        $chars[$brightness]
    }

    if(Test-Path $Path) 
    {
        $Path = Get-Item $Path
        $bitmap = [Drawing.Bitmap]::FromFile($Path)
    }
    else 
    {
        $IESettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if ($IESettings.ProxyEnable -eq 1)
        {
            $response = Invoke-WebRequest $Path -ProxyUseDefaultCredentials -Proxy "http:\\$($IESettings.ProxyServer)"
        }
        else
        {
            $response = Invoke-WebRequest $Path
        }
        $bitmap = [Drawing.Bitmap]::FromStream($response.RawContentStream)
    }

    # Resize image to match pixels to characters on the console.
    $x = $host.UI.RawUI.BufferSize.Width - 1 # If 1 is not subtracted, lines will wrap
    $scale = $x / $bitmap.Size.Width
    # Divide scaled height by 2.2 to compensate for characters being taller than
    # they are wide.
    [int]$y = $bitmap.Size.Height * $scale / $CharHeightWidthRatio
    $bitmap = New-Object System.Drawing.Bitmap -ArgumentList @($bitmap, [Drawing.Size]"$x,$y")
    Clear-Host
    for ($y = 0; $y -lt $bitmap.Size.Height; $y++) 
    {
        for ($x = 0; $x -lt $bitmap.Size.Width; $x++) 
        {
            $pixel = $bitmap.GetPixel($x, $y)
            if ($IsGrayscale) 
            {
                $Color = [ConsoleColor]::White
            }
            else 
            {
                $Color = Get-PixelConsoleColor $pixel
            }
            $character = Get-PixelChar $pixel
            Write-Host $character -ForegroundColor $Color -NoNewline
        }
        Write-Host
    }
}

function Set-CertTrust 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -match '^https\W+')
    {
        Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Verbose 'Using TrustAllCertsPolicy'
    }
    else 
    {
        Write-Verbose 'Not using TrustAllCertsPolicy'
    }
}

function Set-Proxy 
{
    #PS v2
    [CmdletBinding()]

    $IESettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($IESettings.ProxyEnable -eq 1)
    {
        Write-Verbose "Checking proxy $($IESettings.ProxyServer) availablity"
        if(Test-Connection $($IESettings.ProxyServer).Remove($($IESettings.ProxyServer).IndexOf(':')) -Count 1 -Quiet)
        {
            Write-Verbose 'Setting proxy usage'
            $script:PSDefaultParameterValues = @{
                'Invoke-RestMethod:Proxy'    = "http://$($IESettings.ProxyServer)"
                'Invoke-WebRequest:Proxy'    = "http://$($IESettings.ProxyServer)"
                '*:ProxyUseDefaultCredentials' = $true
            }
        }
        else 
        {
            Write-Verbose 'Proxy server not responding'
        }
    }
    else
    {   
        if ($IESettings.AutoConfigURL)
        {     
            $WebClient = New-Object System.Net.WebClient
            $Proxy = $WebClient.DownloadString($IESettings.AutoConfigURL) -split "`n" | Where-Object {
                $_ -match 'PROXY\s+\w.+'
            }
            $Proxy = Get-Random -InputObject $($Proxy -replace '.*"PROXY ' -replace ' PROXY ' -replace '";' -replace ' ' -split ';')
            Write-Verbose "Checking proxy $($Proxy -replace ':.*') availablity"
            if(Test-Connection $($Proxy -replace ':.*') -Count 1 -Quiet)
            {
                Write-Verbose 'Setting proxy usage'
                $script:PSDefaultParameterValues = @{
                    'Invoke-RestMethod:Proxy'    = "http://$Proxy"
                    'Invoke-WebRequest:Proxy'    = "http://$Proxy"
                    '*:ProxyUseDefaultCredentials' = $true
                }
            }
            else 
            {
                Write-Verbose 'Proxy server not responding'
            }
        }
        else 
        {
            Write-Verbose 'Not using proxy'
        }
    }
}

function Get-GeoLocation 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                    If ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                    {
                        $true
                    } 
                    Else
                    {
                        Throw "`n$_ is not an IPV4 Address!"
                    }
        })]
        [string[]]$IPAddress
    )
    BEGIN {Set-Proxy}
    PROCESS {
        foreach ($IP in $IPAddress)
        {
            $infoService = "http://freegeoip.net/xml/$IP"
            $geoip = Invoke-RestMethod -Method Get -Uri $infoService
            $geoip.Response
        }
    }
    END {}
}

function Get-HostAddresses 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Hostname
    )
    BEGIN {Set-Proxy}
    PROCESS {
        foreach ($singlehost in $Hostname)
        {
            $Lookup = [System.Net.Dns]::GetHostAddresses($singlehost)
            foreach ($singlelookup in $Lookup)
            {
                $props = @{
                    'Hostname' = $singlehost
                    'IPAddress' = $singlelookup.IPAddressToString
                }
                $Obj = New-Object -TypeName PSObject -Property $props
                $Obj
            }
        }
    }
    END{}
}

function Get-ShutdownInfo 
{
    Get-EventLog -LogName system -InstanceId 2147484722 -Source user32 |
    ForEach-Object {
        $Result = 'Object' | Select-Object -Property ComputerName, TimeWritten, User, Reason, Action, Executable
    
        $Result.TimeWritten = $_.TimeWritten
        $Result.User = $_.ReplacementStrings[6]
        $Result.Reason = $_.ReplacementStrings[2]
        $Result.Action = $_.ReplacementStrings[4]
        $Result.Executable = Split-Path -Path $_.ReplacementStrings[0] -Leaf
        $Result.ComputerName = $_.MachineName
    
        $Result 
    }
} 

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
        [Parameter(Position = 2)][ValidateSet('None','Info','Warning','Error')]
        [System.Windows.Forms.ToolTipIcon]$BalloonTipIcon = 'None',
        [Parameter(Position = 3)]
        [int]$Timeout = 0,
        [Parameter(Position = 4)]
        [string]$IconPath
    )
    BEGIN   {

        if ($global:NotifyIconObject)
        {
            Write-Verbose 'Removing copy of previous object'
            $global:NotifyIconObject.Visible = $false
            $global:NotifyIconObject.Dispose()
            Remove-Variable -Name NotifyIconObject -Force -ErrorAction SilentlyContinue
        }
        $global:NotifyIconObject= New-Object System.Windows.Forms.NotifyIcon
        $global:NotifyIconObject.Visible = $true
    }
    PROCESS {
        if ($iconPath) 
        {
            $global:NotifyIconObject.Icon = $iconPath
        }

        if($global:NotifyIconObject.Icon -eq $null)
        {
            #Set a Default Icon otherwise the balloon will not show
            $global:NotifyIconObject.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon([System.Windows.Forms.Application]::ExecutablePath)
        }
		
        $NotifyIconObject.ShowBalloonTip($Timeout, $BalloonTipTitle, $BalloonTipText, $BalloonTipIcon)
    }
    END {
            if (Get-EventSubscriber NotifyObject -ErrorAction SilentlyContinue){Unregister-Event NotifyObject -Force}
 
            $global:NotifyTimer = New-Object System.Timers.Timer
            if ($Timeout -eq 0){$Timeout = 10000}
            $global:NotifyTimer.Interval = $Timeout
            $global:NotifyTimer.Enabled=$True
            $Action = {       
                        $global:NotifyIconObject.Visible = $false
                        $global:NotifyIconObject.Dispose()
                      } 
            [void](Register-ObjectEvent -InputObject $global:NotifyTimer -EventName elapsed -SourceIdentifier NotifyObject -Action $Action)
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-CBRRatesChart 
{
    param(
        [Parameter(Mandatory = $true,Position = 0)]
        [ValidateSet(
                'AUD','AZN','GBP','AMD','BYR','BGN','BRL','HUF','DKK','USD','EUR',
                'INR','KZT','CAD','KGS','CNY','MDL','NOK','PLN','RON','XDR','SGD',
                'TJS','TRY','TMT','UZS','UAH','CZK','SEK','CHF','ZAR','KRW','JPY','LVL','LTL')]
        [ValidateCount(2,35)][String[]]$Currency,
        [Parameter(Mandatory = $false,Position = 1)][ValidateSet('Column','Line')][string]$Type = 'Column',
        [Parameter(Mandatory = $false,Position = 2)][string]$Output = $PWD,
        [Parameter(Mandatory = $false,Position = 3)][datetime]$DateRangeFrom = $(Get-Date -Day 1),
        [Parameter(Mandatory = $false,Position = 4)][datetime]$DateRangeTo = $(Get-Date),
        [Parameter(Mandatory = $false,Position = 5)][string]$FileName,
        [Parameter(Mandatory = $false,Position = 6)][switch]$NoLabel
    )

    [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms.DataVisualization')

    if ($DateRangeFrom.Date -gt $DateRangeTo.Date)
    {
        Write-Verbose 'Указанный период DateRangeFrom позже чем DateRangeTo. Используются значения по умолчанию.'
        $DateRangeFrom = $(Get-Date -Day 1)
        $DateRangeTo = $(Get-Date)
    }

    if ((Get-Date -Date $DateRangeFrom -Format MMyy) -eq (Get-Date -Date $DateRangeTo -Format MMyy))
    {
        $datesrange = "$([System.Globalization.DateTimeFormatInfo]::CurrentInfo.GetMonthName($DateRangeFrom.Month)) $($DateRangeFrom.Year)"
    }
    else
    {
        $datesrange = "$($DateRangeFrom.ToShortDateString()) по $($DateRangeTo.ToShortDateString())"
    }

    $dates = @()
    (New-TimeSpan -Start $DateRangeFrom -End $DateRangeTo | Select-Object -ExpandProperty Days)..0 |
    ForEach-Object {
        $dates += (Get-Date).AddDays(-$_)
    }
    Write-Verbose "Запрашивается информация за $($dates.Count) дней. С $($DateRangeFrom.ToShortDateString()) по $($DateRangeTo.ToShortDateString())"
    $DataSet = @()
    $progress_counter = 0
    $dates | ForEach-Object { 
        $day = $_
        Write-Progress -Activity 'Получение информации' `
        -Status "Запрашивается информацию по курсам валют за $($day.ToShortDateString())" `
        -PercentComplete $($progress_counter / (New-TimeSpan -Start $DateRangeFrom -End $DateRangeTo).Days * 100)
        $progress_counter++
        Write-Verbose "Запрашивается информацию по курсам валют за $($day.ToShortDateString())"
        $request = Get-CBRRates -Date $day -Currency $Currency
        $Currency | ForEach-Object {
            Invoke-Expression ('$' + "$_" + ' = $request | ? {$_.CharCode -eq ' + "'$_'}")
        }

        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name Date -Value $request.Date[0]

        $Currency | ForEach-Object { 
            $CurrencyItem = $_.ToUpper()
            $object | Add-Member -MemberType NoteProperty -Name $_ -Value (Invoke-Expression ('$' + "$CurrencyItem" + '.Value'))
        }
        $DataSet += $object
    }

    $datasource = Invoke-Expression ('$'+ 'dataset | Select Date,' + "$($Currency -join ',')" + ' -Unique')

    # chart object
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $chart.Width = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
    $chart.Height = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
    $chart.BackColor = [System.Drawing.Color]::White
 
    # title 
    [void]$chart.Titles.Add("Курсы валют $datesrange")
    $chart.Titles[0].Font = New-Object -TypeName System.Drawing.Font('Tahoma', 14, [System.Drawing.FontStyle]::Bold)
    $chart.Titles[0].Alignment = 'topLeft'
 
    # chart area 
    $chartarea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chartarea.Name = 'ChartArea1'
    $chartarea.AxisY.Title = 'Стоимость РУБ'
    $chartarea.AxisY.TitleFont = New-Object -TypeName System.Drawing.Font('Tahoma', 14, [System.Drawing.FontStyle]::Bold)
    $chartarea.AxisX.Title = 'Дневные курсы ЦБ РФ'
    $chartarea.AxisX.TitleFont = New-Object -TypeName System.Drawing.Font('Tahoma', 14, [System.Drawing.FontStyle]::Bold)
    $chartarea.AxisY.Interval = 2.5
    $chartarea.AxisX.Interval = 1
    $chart.ChartAreas.Add($chartarea)

    $chart.ChartAreas['ChartArea1'].AxisX.LabelStyle.Font = New-Object -TypeName System.Drawing.Font('Tahoma', 12, [System.Drawing.FontStyle]::Bold)
    #$chart.ChartAreas["ChartArea1"].AxisX.LabelStyle.Angle = 90 #90 #0 #-90 #наклон текста дат
    $chart.ChartAreas['ChartArea1'].AxisX.IsLabelAutoFit = $true
   
   
    $PositionX = 35
    $PositionY = 1.5
    $column = 1
   
    $colorrange1 = 100
    $colorrange2 = 250

    $Currency | ForEach-Object {
        $CurrencyItem = $_

        Invoke-Expression ('$legend' + $CurrencyItem + ' = New-Object System.Windows.Forms.DataVisualization.Charting.Legend')
        Invoke-Expression ('$legend' + $CurrencyItem + ".Name = 'Legend $CurrencyItem'")
        Invoke-Expression ('$legend' + 
        $CurrencyItem + '.Position = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.ElementPosition (' + "$PositionX, $PositionY" + ', 25, 3.3)')
        Invoke-Expression ('$legend' + $CurrencyItem + '.BackColor = [System.Drawing.Color]::White')
        Invoke-Expression ('$chart.Legends.Add(' + '$legend' + $CurrencyItem + ')')
        $PositionX += 20
        $column++

        if(($column % 4) -eq 0)
        {
            $PositionY += 3.3
            $PositionX = 35
        }
        
        if($colorrange1 -ge $colorrange2)
        {
            do {$colorrange1 = $colorrange1 - 30}
            while ($colorrange1 -ge $colorrange2)
        }

        [void]$chart.Series.Add("$CurrencyItem")
        $chart.Series["$CurrencyItem"].ChartType = $Type #"Column"#"Line"
        $chart.Series["$CurrencyItem"].IsVisibleInLegend = $true
        $chart.Series["$CurrencyItem"].BorderWidth  = 3
        $chart.Series["$CurrencyItem"].ChartArea = 'ChartArea1'
        $chart.Series["$CurrencyItem"].Legend = "Legend $CurrencyItem"
        $chart.Series["$CurrencyItem"].Color = Convert-RGBToHex -Red (Get-Random -Minimum $colorrange1 -Maximum $colorrange2) `
        -Green (Get-Random -Minimum $colorrange1 -Maximum $colorrange2) `
        -Blue (Get-Random -Minimum $colorrange1 -Maximum $colorrange2)
   
        if ($colorrange1 -lt 240) 
        {
            $colorrange1 += 30 #10
        }
        else 
        {
            $colorrange1 = 100
        }
        if ($colorrange2 -gt 15) 
        {
            $colorrange2 -= 30 #10
        }
        else 
        {
            $colorrange2 = 250
        }

        [void]$chart.Series.Add("$CurrencyItem MIN")
        $chart.Series["$CurrencyItem MIN"].IsVisibleInLegend = $true
        $chart.Series["$CurrencyItem MIN"].Legend = "Legend $CurrencyItem"
        $colormin = Convert-RGBToHex -Red (Get-Random -Minimum 0 -Maximum 100) `
        -Green (Get-Random -Minimum 175 -Maximum 255) `
        -Blue (Get-Random -Minimum 0 -Maximum 100)
        $chart.Series["$CurrencyItem MIN"].Color = $colormin

        [void]$chart.Series.Add("$_ MAX")
        $chart.Series["$CurrencyItem MAX"].IsVisibleInLegend = $true
        $chart.Series["$CurrencyItem MAX"].Legend = "Legend $CurrencyItem"
        $colormax = Convert-RGBToHex -Red (Get-Random -Minimum 175 -Maximum 255) `
        -Green (Get-Random -Minimum 0 -Maximum 100) `
        -Blue (Get-Random -Minimum 0 -Maximum 100)
        $chart.Series["$CurrencyItem MAX"].Color = $colormax

        $chart.Series["$CurrencyItem"].Font = New-Object -TypeName System.Drawing.Font('Tahoma', 8, [System.Drawing.FontStyle]::Bold) #values label

        $i = 0
        $datasource | ForEach-Object {
            $datasourceitem = $_

            [void]$chart.Series["$CurrencyItem"].Points.addxy( $datasourceitem.Date , (Invoke-Expression ('$datasourceitem.' + $CurrencyItem )))
            if (-not$NoLabel)
            {
                $chart.Series["$CurrencyItem"].Points[$i].Label = ('{0:N2}' -f (Invoke-Expression ('$datasourceitem.' + $CurrencyItem ))) # текст над линией/столбцом
                $chart.Series["$CurrencyItem"].Points[$i].LabelBackColor = [System.Drawing.Color]::Azure # цвет текста над линией/столбцом
            }
            $i++
        }      

        $maxvalueeur = $chart.Series["$CurrencyItem"].Points.FindMaxByValue() 
        $maxvalueeur.Color = $colormax
        $minvalueeur = $chart.Series["$CurrencyItem"].Points.FindMinByValue() 
        $minvalueeur.Color = $colormin

        if ($Type -eq 'Column')
        {
            $chart.Series["$CurrencyItem"]['DrawingStyle'] = 'Cylinder'
        }
    }
    if (-not(Test-Path $Output))
    {
        [void](New-Item -Path $Output -ItemType Directory -Force)
    }
    if (-not($FileName))
    {
        $FileName = $($Currency -join '')
    }
    try
    {
        $chart.SaveImage("$Output\$FileName.png",'png')
        Write-Verbose "График сохранен $Output\$FileName.png"
    }
    catch
    {
        Write-Warning $Error[0].Exception.Message
    }
}

function Get-CBRRates 
{
    #Get-CBRRates
    #Get-CBRRates -CompareToDate (Get-Date).AddDays(1) | ft -Wrap -AutoSize
    #Get-CBRRates -Date (Get-Date 01.01.2012) -CompareToDate (Get-Date) -Currency EUR,CNY,USD | ft
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0)]
        [Alias('Day')]
        [DateTime]$Date = $(Get-Date),

        [Parameter(Mandatory = $false)]
        [DateTime]$CompareToDate,

        [Parameter(Mandatory = $false)]
        [ValidateSet(
                'AUD','AZN','GBP','AMD','BYR','BGN','BRL','HUF','DKK','USD','EUR',
                'INR','KZT','CAD','KGS','CNY','MDL','NOK','PLN','RON','XDR','SGD',
        'TJS','TRY','TMT','UZS','UAH','CZK','SEK','CHF','ZAR','KRW','JPY','LVL','LTL')]
        [String[]]$Currency,

        [Parameter(Mandatory = $false)]
        [Alias('Source')]
        [String]$DefaultCBRLinkSource = 'http://www.cbr.ru/scripts/XML_daily.asp?date_req=',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default','Unicode','UTF8')]
        [Alias('Encode')]
        [String]$CodePage = 'Default',

        [Parameter(Mandatory = $false)]
        [Alias('SaveTo')]
        [String]$Output,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Overwrite','Append')]
        [Alias('SaveAction')]
        [String]$OutputAction
    )
    BEGIN
    {
        if ($Date.Date -eq $CompareToDate.Date)
        {
            [bool]$CompareToDate = $false
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Date равно CompareToDate, будет использован только $Date"
        }
        elseif ($Date.Date -lt $CompareToDate.Date)
        {
            switch ((Get-Date -Date $CompareToDate).DayOfWeek.value__)
            {
                6
                {
                    $CompareToDate = $CompareToDate.AddDays(2)
                }
                0
                {
                    $CompareToDate = $CompareToDate.AddDays(1)
                }
            }
        }

        if (((Get-Date -Date $Date).DayOfWeek.value__) -eq 0)
        {
            $Date = (Get-Date -Date $Date).AddDays(-2) 
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Указанная дата приходится на воскресенье, будет использована дата $Date"
        }
        if (((Get-Date -Date $Date).DayOfWeek.value__) -eq 6)
        {
            $Date = (Get-Date -Date $Date).AddDays(-1)
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Указанная дата приходится на субботу, будет использована дата $Date"
        }
        [String]$Date = $(Get-Date -Date $Date -UFormat '%d/%m/%Y')
    }
    PROCESS{
        [xml]$XML = (Get-ExtendedWebClient -Encoding $CodePage -Timeout 3000).DownloadString("$($DefaultCBRLinkSource)$($Date)")
        
        if ($XML -eq $null)
        { 
            Write-Warning "$(Get-Date -UFormat '%H:%M:%S') Ошибка получения информации $($DefaultCBRLinkSource)$($Date)"
            break
        }

        Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Получение информации $($DefaultCBRLinkSource)$($Date)"
        $Rates = $XML.ValCurs.Valute          
        $RatesObject = @()
        $Rates | ForEach-Object {
            $props = @{
                'Date'   = $Date -replace '/', '.'
                'ID'     = $_.ID
                'NumCode' = $_.NumCode
                'CharCode' = $_.CharCode
                'Nominal' = $_.Nominal
                'Name'   = $_.Name
                'Value'  = [decimal]($_.Value -replace ',', '.')
            }
            $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
            $RatesObject += $Obj
        }

        $RatesObject = $RatesObject | Select-Object Date, ID, NumCode, CharCode, Name, Nominal, Value


        if ($CompareToDate)
        {
            if (((Get-Date -Date $CompareToDate).DayOfWeek.value__) -eq 0)
            {
                $CompareToDate = (Get-Date -Date $CompareToDate).AddDays(-2) 
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Указанная дата для сравнения приходится на воскресенье, будет использована дата $CompareToDate"
            }
            if (((Get-Date -Date $CompareToDate).DayOfWeek.value__) -eq 6)
            {
                $CompareToDate = (Get-Date -Date $CompareToDate).AddDays(-1)
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Указанная дата для сравнения приходится на субботу, будет использована дата $CompareToDate"
            }

            [String]$CompareToDate = $(Get-Date -Date $CompareToDate -UFormat '%d/%m/%Y')
            [xml]$XMLCompare = (Get-WebClient -Encoding $CodePage).DownloadString("$($DefaultCBRLinkSource)$($CompareToDate)")
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Получение информации $($DefaultCBRLinkSource)$($CompareToDate)"
            $RatesCompare = $XMLCompare.ValCurs.Valute




            $CompareRatesObject = @()
            $RatesCompare | ForEach-Object {
                $CompareItem = $_
                $CompareItemValue = [decimal]($CompareItem.Value -replace ',', '.')
                $MatchItem = $RatesObject | Where-Object {
                    $_.CharCode -eq $CompareItem.CharCode
                }
                if ($MatchItem.Value -gt $CompareItemValue)
                {
                    $Changed = '-'
                }
                elseif($MatchItem.Value -lt $CompareItemValue)
                {
                    $Changed = '+'
                }
                else
                {
                    $Changed = $null
                }
                $props = @{
                    'ID'                               = $MatchItem.ID
                    'NumCode'                          = $MatchItem.NumCode
                    'CharCode'                         = $MatchItem.CharCode
                    'Nominal'                          = $MatchItem.Nominal
                    'Name'                             = $MatchItem.Name
                    "$($MatchItem.Date)"               = $MatchItem.Value
                    "$($CompareToDate -replace '/','.')" = $CompareItemValue
                    'OffsetValue'                      = "$Changed$([System.Math]::Abs(([System.Math]::Round(($MatchItem.Value - $CompareItemValue),4))))"
                    'Offset%'                          = "$Changed$([System.Math]::Abs(([System.Math]::Round((100 - $MatchItem.Value / ($CompareItemValue / 100)),4))))"
                }
                $MatchObject = New-Object -TypeName System.Management.Automation.PSObject -Property $props
                $CompareRatesObject += $MatchObject
            }
            $RatesObject = $CompareRatesObject | Select-Object ID, NumCode, CharCode, Name, Nominal, "$($MatchItem.Date)", "$($CompareToDate -replace '/','.')", OffsetValue, Offset%
        }

        if ($Currency) 
        {
            $CustomRates = @()
            foreach ($CurrencyItem in $Currency)
            {
                $CustomRates += $RatesObject |  Where-Object {
                    $_.CharCode -eq $CurrencyItem
                }
            }
            $RatesObject = $CustomRates
        }

        if ($Output) 
        {
            $params = @{
                'Encoding' = $CodePage
                'FilePath' = $Output
            }
            if ($OutputAction -eq 'Overwrite') 
            {
                $RatesObject | Out-File @params -Force
            }
            elseif($OutputAction -eq 'Append') 
            {
                $RatesObject | Out-File @params -Append -Force
            }
            else 
            {
                $RatesObject | Out-File @params -Append -Force
            }              
        }
        else 
        {
            Write-Output $RatesObject
        }
        if (-not($CompareToDate))
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Данные по курсам валют за $Date"
        }
        else 
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Данные по курсам валют за $Date со сравнением относительно $CompareToDate"
        }

        if ($Currency) 
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по валютам с буквенным кодом:`n`n$($Currency -join ',')`n`n"
        }
        else 
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по всем валютам.`n"
        }
            
    }
    END{
     
    }
}

function Get-CBRMetallRates 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0)]
        [Alias('Day')]
        [DateTime]$Date = $(Get-Date),

        [Parameter(Mandatory = $false)]
        [DateTime]$CompareToDate,

        [Parameter(Mandatory = $false)]
        [ValidateSet('XAU','XAG','XPT','XPD')]
        [String[]]$MetallCode,

        [Parameter(Mandatory = $false)]
        [ValidateSet(
                'AUD','AZN','GBP','AMD','BYR','BGN','BRL','HUF','DKK','USD','EUR',
                'INR','KZT','CAD','KGS','CNY','MDL','NOK','PLN','RON','XDR','SGD',
        'TJS','TRY','TMT','UZS','UAH','CZK','SEK','CHF','ZAR','KRW','JPY','LVL','LTL')]
        [String]$Currency,

        [Parameter(Mandatory = $false)]
        [Alias('Source')]
        [String]$DefaultCBRLinkSource = 'http://www.cbr.ru/scripts/xml_metall.asp?date_req1=',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default','Unicode','UTF8')]
        [Alias('Encode')]
        [String]$CodePage = 'Default',

        [Parameter(Mandatory = $false)]
        [Switch]$RawAll,

        [Parameter(Mandatory = $false)]
        [Alias('SaveTo')]
        [String]$Output,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Overwrite','Append')]
        [Alias('SaveAction')]
        [String]$OutputAction
    )
    BEGIN
    {
        if ($Date.Date -eq $CompareToDate.Date)
        {
            [bool]$CompareToDate = $false
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Date равно CompareToDate, будет использован только Date $($Date.ToShortDateString())"
        }

        if (-not $CompareToDate)
        {
            if ($Date.DayOfWeek.value__ -eq 1)
            {
                [String]$CompareDefaultDate = Get-Date -Date ($Date.AddDays(-2)) -UFormat '%d/%m/%Y'
            }
            else
            {
                [String]$CompareDefaultDate = Get-Date -Date ($Date.AddDays(-1)) -UFormat '%d/%m/%Y'
            }
            $Mode = 'Simple'
        }
        else
        {
            $Mode = 'Compare'
            $CompareDefaultDate = Get-Date -Date $CompareToDate -UFormat '%d/%m/%Y'
            if ($CompareToDate.Date -ge $Date.Date)
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') CompareToDate больше или равно Date. Используется только Date."
                $CompareToDate = $Date
                $Mode = 'Simple'
            }

            if ($Date.DayOfWeek.value__ -eq 1)
            {
                $CompareToDate = $CompareToDate.AddDays(-2)
            }
            if ($Date.DayOfWeek.value__ -eq 0)
            {
                $CompareToDate = $CompareToDate.AddDays(-1)
            }

            [String]$CompareToDate = $(Get-Date -Date $CompareToDate -UFormat '%d/%m/%Y')
        }

        [String]$Date = $(Get-Date -Date $Date -UFormat '%d/%m/%Y')
    }
    PROCESS{
        [xml]$XML = (Get-WebClient -Encoding $CodePage).DownloadString("$($DefaultCBRLinkSource)$($CompareDefaultDate)&date_req2=$($Date)")
        Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Получение информации $($DefaultCBRLinkSource)$($CompareDefaultDate)&date_req2=$($Date)"
        if ($XML.Metall.Record -ne $null)
        {
            $Rates = $XML.Metall.Record
            $MinDate = $Rates.Date | Measure-Object -Minimum | Select -ExpandProperty Minimum
            $MaxDate = $Rates.Date | Measure-Object -Maximum | Select -ExpandProperty Maximum
            $Rates = $Rates | Where-Object {
                $_.Date -eq $MinDate -or $_.Date -eq $MaxDate
            }
            $RatesObject = @()
            $Rates | ForEach-Object {
                $props = @{
                    'Date'   = $_.Date
                    'Code'   = $_.Code
                    'CharCode' = switch ($_.Code)
                    {   
                        1 
                        {
                            'XAU'
                        }
                        2 
                        {
                            'XAG'
                        }
                        3 
                        {
                            'XPT'
                        }
                        4 
                        {
                            'XPD'
                        }
                    }
                    'Name'   = switch ($_.Code)
                    {   
                        1 
                        {
                            'Золото'
                        }
                        2 
                        {
                            'Серебро'
                        }
                        3 
                        {
                            'Платина'
                        }
                        4 
                        {
                            'Палладий'
                        }
                    }
                    'Buy'    = $_.Buy
                    'Sell'   = $_.Sell -replace ',', '.'
                }
                $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
                $RatesObject += $Obj
            }
            $RatesObject = $RatesObject | Select-Object Date, Code, CharCode, Name, Sell

            $Previous = $RatesObject |
            Where-Object {
                $_.Date -eq $Rates.Date[0]
            } |
            Sort-Object Code
            $Current = $RatesObject |
            Where-Object {
                $_.Date -eq $Rates.Date[-1]
            } |
            Sort-Object Code
            if ($Previous.Date[0] -ne $Current.Date[0])
            {
                $CompareRatesObject = @()
            
                for($i = 0;$i -lt 4;$i++)
                {
                    if ($Previous.Sell[$i] -gt $Current.Sell[$i])
                    {
                        $Changed = '-'
                    }
                    elseif($Previous.Sell[$i] -lt $Current.Sell[$i])
                    {
                        $Changed = '+'
                    }
                    else
                    {
                        $Changed = $null
                    }

                    $props = @{
                        'Code'               = $Current.Code[$i]
                        'CharCode'           = $Current.CharCode[$i]
                        'Name'               = $Current.Name[$i]
                        "$($Previous.Date[0])" = $Previous.Sell[$i]
                        "$($Current.Date[0])" = $Current.Sell[$i]
                        'OffsetValue'        = "$Changed$([System.Math]::Abs(([System.Math]::Round(($Current.Sell[$i] - $Previous.Sell[$i]),4))))"
                        'Offset%'            = "$Changed$([System.Math]::Abs(([System.Math]::Round((100 - $Current.Sell[$i] / ($Previous.Sell[$i] / 100)),4))))"
                    }
                    $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
                    $CompareRatesObject += $Obj
                }
                $RatesObject = $CompareRatesObject | Select-Object Code, CharCode, Name, "$($Previous.Date[0])", "$($Current.Date[0])", OffsetValue, Offset%
            }
            if ($MetallCode) 
            {
                $CustomRates = @()
                foreach ($CurrencyItem in $MetallCode)
                {
                    $CustomRates += $RatesObject |  Where-Object {
                        $_.CharCode -match $CurrencyItem
                    }
                }
                $RatesObject = $CustomRates
            }
            if ($Currency)
            {
                $CBRRates = Get-CBRRates -Currency $Currency | Select-Object -ExpandProperty Value
                $CurrencyRatesObject = @()
                switch ($Mode)
                {
                    'Simple'  
                    {
                        $RatesObject | ForEach-Object {             
                            $props = @{
                                'Code'   = $_.Code
                                'CharCode' = $_.CharCode
                                'Name'   = $_.Name
                                'Currency' = $Currency
                                'Sell'   = [System.Math]::Round(($_.sell / $CBRRates),4)
                            }
                            $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
                            $CurrencyRatesObject += $Obj
                        }
                        $RatesObject = $CurrencyRatesObject | Select-Object Code, CharCode, Name, Currency, Sell
                    }
                    'Compare' 
                    {
                        $RatesObject | ForEach-Object {
                            if ($_."$($Previous.Date[0])" -gt $_."$($Current.Date[0])")
                            {
                                $Changed = '-'
                            }
                            elseif($_."$($Previous.Date[0])" -lt $_."$($Current.Date[0])")
                            {
                                $Changed = '+'
                            }
                            else
                            {
                                $Changed = $null
                            }
                
                            $props = @{
                                'Code'               = $_.Code
                                'CharCode'           = $_.CharCode
                                'Name'               = $_.Name
                                'Currency'           = $Currency
                                "$($Previous.Date[0])" = [System.Math]::Round(($_."$($Previous.Date[0])" / $CBRRates),4)
                                "$($Current.Date[0])" = [System.Math]::Round(($_."$($Current.Date[0])" / $CBRRates),4)
                                'OffsetValue'        = "$Changed$([System.Math]::Abs(([System.Math]::Round((($_."$($Current.Date[0])" / $CBRRates) - ($_."$($Previous.Date[0])" / $CBRRates)),4))))"
                                'Offset%'            = "$Changed$([System.Math]::Abs(([System.Math]::Round((100 - ($_."$($Current.Date[0])" / $CBRRates) / (($_."$($Previous.Date[0])" / $CBRRates) / 100)),4))))"
                            }
                            $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
                            $CurrencyRatesObject += $Obj
                        }
                        $RatesObject = $CurrencyRatesObject | Select-Object Code, CharCode, Name, Currency, "$($Previous.Date[0])", "$($Current.Date[0])", OffsetValue, Offset%
                    }
                }
            }
            if ($RawAll)
            {
                Write-Warning 'При выборе -RawAll отображается исходная информация.'
                $RatesObject = $XML.Metall.Record
            }
            if ($Output) 
            {
                $params = @{
                    'Encoding' = $CodePage
                    'FilePath' = $Output
                }
                if ($OutputAction -eq 'Overwrite') 
                {
                    $RatesObject | Out-File @params -Force
                }
                elseif($OutputAction -eq 'Append') 
                {
                    $RatesObject | Out-File @params -Append -Force
                }
                else 
                {
                    $RatesObject | Out-File @params -Append -Force
                }              
            }
            else 
            {
                Write-Output $RatesObject
            }

            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по курсам металлов за $Date."

            if ($Mode -eq 'Compare' -and (-not $RawAll)) 
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по изменениям курсов относительно даты $(Get-Date -Date $Previous.Date[0] -UFormat '%d/%m/%Y')."
            }
            if ($Currency)
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации используя валюту $($Currency.ToUpper())."
            }

            if (($MetallCode) -and (-not$RawAll)) 
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по металлам с буквенным кодом: $($MetallCode -join ',').`n`n"
            }
            else 
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Отображение информации по всем доступным металлам.`n"
            }
        }
        else
        {
            Write-Warning "Отсутствуют данные по курсам драгоценных металлов за выбранную дату ($Date)"
        }
    }
    END{
     
    }
}

function Get-CBRBankInfo 
{
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false)]
        [String[]]$NamePattern,

        [Parameter(Mandatory = $false)]
        [Int[]]$BicPattern,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default','Unicode','UTF8')]
        [Alias('Encode')]
        [String]$CodePage = 'Default',

        [Parameter(Mandatory = $false)]
        [Alias('SaveTo')]
        [String]$Output,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Overwrite','Append')]
        [Alias('SaveAction')]
        [String]$OutputAction,

        [Parameter(Mandatory = $false)]
        [Alias('Source')]
        [String]$DefaultCBRLinkSource = 'http://www.cbr.ru/scripts/XML_bic.asp?name=&bic='

    )
    BEGIN
    {
    }
    PROCESS{
        [xml]$XML = (Get-WebClient -Encoding $CodePage).DownloadString($DefaultCBRLinkSource)
        $Banks = $XML.BicCode.Record

        if ($NamePattern -ne $null -or $BicPattern -ne $null)
        {
            $Searcher = @()
            if ($NamePattern -ne $null -and $BicPattern -eq $null)
            {
                foreach ($Name in $NamePattern)
                {
                    $Searcher += $Banks | Where-Object {
                        $_.ShortName -match $Name
                    }
                }
            }
            if ($NamePattern -eq $null -and $BicPattern -ne $null)
            {
                foreach ($Bic in $BicPattern)
                {
                    $Searcher += $Banks | Where-Object {
                        $_.Bic -match $Bic
                    }
                }
            }
            if ($NamePattern -ne $null -and $BicPattern -ne $null)
            {   
                $CombinedSearcher = @()
                foreach ($Name in $NamePattern)
                {
                    $CombinedSearcher += $Banks | Where-Object {
                        $_.ShortName -match $Name
                    }
                }
                foreach ($Bic in $BicPattern)
                {
                    $Searcher += $CombinedSearcher | Where-Object {
                        $_.Bic -match $Bic
                    }
                }
            }
            $Banks = $Searcher
        }
        if ($Output) 
        {
            $params = @{
                'Encoding' = 'UTF8'
                'FilePath' = $Output
            }
            if ($OutputAction -eq 'Overwrite') 
            {
                $Banks | Out-File @params -Force
            }
            elseif($OutputAction -eq 'Append') 
            {
                $Banks | Out-File @params -Append -Force
            }
            else 
            {
                $Banks | Out-File @params -Append -Force
            }              
        }
        else 
        {
            Write-Output $Banks
        }
            
    }
    END{
     
    }
}

function Invoke-Unzip 
{
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true)]
        [String]$OutputPath,

        [Parameter(Mandatory = $true)]
        [String]$InputFile,

        [Parameter(Mandatory = $false)]
        [Switch]$RemoveZipOnSuccess
    )
    BEGIN{
        $Obj = New-Object -ComObject Shell.Application
    }
    PROCESS{
        if (Test-Path -Path $InputFile)
        {
            $OutputPath = "$($OutputPath)$($InputFile -replace [regex]::Escape($OutputPath) -replace '.zip')"
            if (-not(Test-Path -Path $OutputPath))
            {
                [void]$(New-Item -Path $OutputPath -ItemType Directory -Force)
            }
            else
            {
                [void]$(Remove-Item -Path $OutputPath -Recurse -Force -Confirm:$false)
                [void]$(New-Item -Path $OutputPath -ItemType Directory -Force)
            }
            $ZipFile = $Obj.NameSpace($InputFile)
            $UnzipTo = $Obj.NameSpace($OutputPath)
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Выполняется распаковка архива $InputFile в директорию $OutputPath"
            $UnzipTo.CopyHere($ZipFile.Items())
            if ((Get-ChildItem $OutputPath).Count -gt 0)
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Распаковка файлов в директорию $OutputPath завершена."
                if ($RemoveZipOnSuccess)
                {
                    Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Выполняется удаление архива $InputFile"
                    Remove-Item $InputFile -Force -Confirm:$false
                    Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Архив $InputFile удален."
                }
            }
            else 
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') В процессе распаковки файлов в директорию $OutputPath возникла ошибка."
            }
        }
        else 
        {
            Write-Warning "Указанный файл ($InputFile) не найден."
            Write-Verbose "Указанный файл ($InputFile) не найден."
        }
    }
    END{}
}

function Get-CBRBicDB 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0)]
        [Alias('Day')]
        [DateTime]$Date = $(Get-Date),

        [Parameter(Mandatory = $true,Position = 1,HelpMessage = 'Необходимо указать директорию для сохранения файлов.')]
        [Alias('SaveTo')]
        [String]$Output,

        [Parameter(Mandatory = $false)]
        [Alias('Source')]
        [String]$DefaultCBRLinkSource = 'http://www.cbr.ru/mcirabis/BIK/'
    )
    BEGIN
    {
        [String]$Date = $(Get-Date -Date $Date -UFormat '%d%m%Y')
    }
    PROCESS{
        if (-not(Test-Path -Path $Output))
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Директория $Output отсутствует. Выполняется создание."
            [void]$(New-Item -Path $Output -ItemType Directory -Force -ErrorVariable OutputCheck -ErrorAction Stop)
            if ($OutputCheck.Count -eq 0)
            {
                Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Директория $Output создана."
            }
        }
        $OutputFile = "$($Output)\bik_db_$($Date).zip"
        Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Выполняется загрузка файла $($DefaultCBRLinkSource)bik_db_$($Date).zip"
        $((Get-WebClient).DownloadFile("$($DefaultCBRLinkSource)bik_db_$($Date).zip",$OutputFile))
        if (Test-Path -Path $OutputFile)
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Файл $($DefaultCBRLinkSource)bik_db_$($Date).zip загружен."
            Invoke-Unzip -InputFile $OutputFile -OutputPath $Output -RemoveZipOnSuccess -Verbose
        }
        else
        {
            Write-Verbose "$(Get-Date -UFormat '%H:%M:%S') Ошибка загрузки файла."
        }
    }
    END{
     
    }
}

function Convert-ToRUB 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,Position = 0)]
        [Int]$Amount,

        [Parameter(Mandatory = $true,Position = 1)]
        [ValidateSet(
                'AUD','AZN','GBP','AMD','BYR','BGN','BRL','HUF','DKK','USD','EUR',
                'INR','KZT','CAD','KGS','CNY','MDL','NOK','PLN','RON','XDR','SGD',
        'TJS','TRY','TMT','UZS','UAH','CZK','SEK','CHF','ZAR','KRW','JPY')]
        [String]$Currency,

        [Parameter(Mandatory = $false,Position = 2)]
        [ValidateRange(-10000, 1)][Int]$DaysOffset = 1
    )
    BEGIN{}
    PROCESS{
        $CompareDay = $(Get-Date).AddDays($DaysOffset)
        $CBR = Get-CBRRates -Currency $Currency -CompareToDate $CompareDay

        $props = @{
            'Amount'                                = $Amount
            'Currency'                              = $Currency.ToUpper()
            "$((Get-Date).ToShortDateString()) Rate" = [System.Math]::Round(($CBR."$((Get-Date).ToShortDateString())" / $CBR.Nominal),4)
            "$((Get-Date).ToShortDateString()) RUB" = [System.Math]::Round(($Amount * $CBR."$((Get-Date).ToShortDateString())" / $CBR.Nominal),4)
            "$($CompareDay.ToShortDateString()) Rate" = [System.Math]::Round(($CBR."$($CompareDay.ToShortDateString())" / $CBR.Nominal),4)
            "$($CompareDay.ToShortDateString()) RUB" = [System.Math]::Round(($Amount* $CBR."$($CompareDay.ToShortDateString())" / $CBR.Nominal),4)
            'Offset%'                               = $CBR.'Offset%'
        }
        $Obj = New-Object -TypeName PSObject -Property $props
        $Obj = $Obj|Select-Object Amount, Currency, "$((Get-Date).ToShortDateString()) Rate", "$((Get-Date).ToShortDateString()) RUB", "$($CompareDay.ToShortDateString()) Rate", "$($CompareDay.ToShortDateString()) RUB", 'Offset%', @{
            l = 'Difference RUB '
            e = {
                $($_."$($CompareDay.ToShortDateString()) RUB")-$($_."$((Get-Date).ToShortDateString()) RUB")
            }
        }
    }
    END{
        Write-Output $Obj
    }
}

function Get-CurrentDateDetailedInfo 
{
    $Date = Get-Date
    $a = @()
    $(Get-Date -Day 01 -Format dd)..$(Get-Date $(Get-Date -Day 01).AddMonths(1).AddDays(-1) -Format dd) | ForEach-Object {
        $p = @{
            'day'        = $(Get-Date -Day $_ -Format dd)
            'dayofweek'  = $(Get-Date -Day $_ -Format dddd)
            'dayofweeknum' = $(Get-Date -Day $_).DayOfWeek.value__
        }
        $o = New-Object -TypeName System.Management.Automation.PSObject -Property $p
        $a += $o
    }
    $a1 = @()
    foreach ($aa in $a)
    {
        $ar = ($aa | Where-Object {
                $_.dayofweeknum -eq 0
        })
        $a1 += $ar
    }
    $a2 = @()
    $i = 1
    foreach ($aa1 in $a1)
    {
        $ar1 = $a|
        Where-Object{
            $_.day -le $aa1.day
        }|
        Sort-Object -Property Day -Descending|
        Select-Object -First 7 |
        Sort-Object -Property Day
        foreach ($aar1 in $ar1)
        {
            $p1 = @{
                'day'        = $aar1.day
                'dayofweek'  = $aar1.dayofweek
                'dayofweeknum' = $aar1.dayofweeknum
                'weeknum'    = $i
            }
            $o1 = New-Object -TypeName System.Management.Automation.PSObject -Property $p1
            $a2 += $o1
        }
        $i++
    }
    $a3 = $a| Where-Object {
        $_.day -gt $a1[-1].day
    }
    foreach ($aa2 in $a3)
    {
        $p2 = @{
            'day'        = $aa2.day
            'dayofweek'  = $aa2.dayofweek
            'dayofweeknum' = $aa2.dayofweeknum
            'weeknum'    = $i
        }
        $o2 = New-Object -TypeName System.Management.Automation.PSObject -Property $p2
        $a2 += $o2
    }
    $props = @{
        'Day'           = $(if ($($Date.Day.ToString().Length) -lt 2)
            {
                "0$($Date.Day)"
            }
            else
            {
                $Date.Day
            }
        )
        'DayOfWeek'     = $(Get-Date -Format dddd)
        'Month'         = $(if ($($Date.Month.ToString().Length) -lt 2)
            {
                "0$($Date.Month)"
            }
            else
            {
                $Date.Month
            }
        )
        'MonthName'     = $(Get-Date -Format MMMM)
        'FirstDayOfMonth' = $(if ($Date.Date.AddDays(-$(($Date.Day)-1)).Day.ToString().Length -lt 2)
            {
                "0$($Date.Date.AddDays(-$(($Date.Day)-1)).Day) ($(Get-Date -Day "0$($Date.Date.AddDays(-$(($Date.Day)-1)).Day)" -Format dddd))"
            }
            else
            {
                "$($Date.Date.AddDays(-$(($Date.Day)-1)).Day) ($(Get-Date -Day "0$($Date.Date.AddDays(-$(($Date.Day)-1)).Day)" -Format dddd))"
            }
        )
        'LastDayOfMonth' = $("$(($Date.Date.AddDays(-$(($Date.Day)-1)) -as [datetime]).AddMonths(1).AddSeconds(-1).Day) ($(Get-Date -Day $(($Date.Date.AddDays(-$(($Date.Day)-1)) -as [datetime]).AddMonths(1).AddSeconds(-1).Day) -Format dddd))")
        'WeekInMonth'   = $("$(($a2 | Where-Object {





                $_.Day -eq (Get-Date -Format dd)
                
                
                
                
                
                }).weeknum) (из $(($a2 | Where-Object {





                $_.Day -eq (Get-Date $((Get-Date -Day 01).AddMonths(1).AddDays(-1)) -Format dd)
        
        
        
        
        
        }).weeknum))")
        'WeekInYear'    = $(Get-Date -UFormat '%V')
        'Year'          = $Date.Year
        'DaysInYear'    = $(if ($(((Get-Date -Date "31.12.$((Get-Date).Year)").DayOfYear)) -eq 365)
            {
                "$(((Get-Date -Date "31.12.$((Get-Date).Year)").DayOfYear)) (невисокосный год)"
            }
            else
            {
                "$(((Get-Date -Date "31.12.$((Get-Date).Year)").DayOfYear)) (високосный год)"
            }
        )
        'DayOfYear'     = $Date.DayOfYear
        'Hour'          = $(if ($($Date.Hour.ToString().Length) -lt 2)
            {
                "0$($Date.Hour)"
            }
            else
            {
                $Date.Hour
            }
        )
        'Minute'        = $(if ($($Date.Minute.ToString().Length) -lt 2)
            {
                "0$($Date.Minute)"
            }
            else
            {
                $Date.Minute
            }
        )
        'Second'        = $(if ($($Date.Second.ToString().Length) -lt 2)
            {
                "0$($Date.Second)"
            }
            else
            {
                $Date.Second
            }
        )
        'Millisecond'   = $Date.Millisecond
    }
    $Obj = New-Object -TypeName System.Management.Automation.PSObject -Property $props
    $Obj | Select-Object `
    Day, 
    DayOfWeek, 
    Month, 
    MonthName, 
    FirstDayOfMonth, 
    LastDayOfMonth, 
    WeekInMonth, 
    WeekInYear, 
    Year, 
    DayOfYear, 
    DaysInYear, 
    Hour, 
    Minute, 
    Second, 
    Millisecond
}

function Get-PSNews 
{
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Navigate2('http://blogs.technet.com/b/heyscriptingguy/')
    $ie.Navigate2('http://www.powershellmagazine.com/',0x1000)
    $ie.Navigate2('http://powershell.org/wp/',0x1000)
    $ie.Navigate2('http://powershell.org/wp/category/announcements/scripting-games/',0x1000)
    $ie.Visible = $true
}

function Invoke-Profile 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,Position = 0)]
        [ValidateSet('AllUsersAllHosts','AllUsersCurrentHost','CurrentUserAllHosts','CurrentUserCurrentHost')]
        [string]$Type,
        [Parameter(Mandatory = $false,Position = 1)]
        [ValidateSet('New','Edit','UsePattern')]
        [string]$Mode
    )
    switch ($Type){
        'AllUsersAllHosts' 
        {
            $file = $PROFILE.AllUsersAllHosts
        }
        'AllUsersCurrentHost' 
        {
            $file = $PROFILE.AllUsersCurrentHost
        }
        'CurrentUserAllHosts' 
        {
            $file = $PROFILE.CurrentUserAllHosts
        }
        'CurrentUserCurrentHost' 
        {
            $file = $PROFILE.CurrentUserCurrentHost
        }
        default 
        {
            $file = $PROFILE
        }
    }
    if (Test-Path $file)
    {
        switch ($Mode)
        {
            'New'
            {
                [void]$(Rename-Item -Path $file -NewName "$file.backup $(Get-Date -Format 'dd.MM.yy-HH-mm-ss')")
                Write-Warning -Message "Found existing profile ps1 file. Renamed to $file.backup $(Get-Date -Format 'dd.MM.yy-HH-mm-ss')"
                [void]$(New-Item -Path $file -ItemType File -Force)
                Write-Warning -Message "Succesfully created $file file."
                Write-Verbose "New mode used. File path $file"
                powershell_ise.exe $file
            }
            'Edit'
            {
                Copy-Item $file -Destination $([io.path]::GetTempFileName()) -PassThru | ForEach-Object {
                    powershell_ise.exe $_.fullname
                }
                Write-Verbose "Edit mode used. File path $file"
            }
            'UsePattern'
            {
                [void]$(Rename-Item -Path $file -NewName "$file.backup $(Get-Date -Format 'dd.MM.yy-HH-mm-ss')")
                Write-Warning -Message "Found existing profile ps1 file. Renamed to $file.backup $(Get-Date -Format 'dd.MM.yy-HH-mm-ss')"
                [void]$(New-Item -Path $file -ItemType File -Force)
                Write-Warning -Message "Succesfully created $file file."
                @'
Set-Location "$env:SystemDrive\"

Import-Module PK-Tools,AutoBrowse,WASP

function gry {
Get-CBRRates -Date (Get-Date).AddDays(-1) -CompareToDate (Get-Date) -Currency EUR,USD | Sort-Object NumCode | ft -Wrap -AutoSize
}

function grt {
Get-CBRRates -CompareToDate (Get-Date).AddDays(1) -Currency EUR,USD | Sort-Object NumCode | ft -Wrap -AutoSize
}

function gmr {
    $today = Get-Date
    if ($today.DayOfWeek.value__ -ne 5)
    {
        $i=-1
        do 
        {
            $compareday = ($today).AddDays($i)
            $i--

        }
        until ($compareday.DayOfWeek.value__ -eq 5)
    }
    else
    {$compareday = ($today).AddDays(-7)}
    Get-CBRMetallRates -CompareToDate $compareday | ft -Wrap -AutoSize
}

New-Alias -Name ctr -Value Convert-ToRUB
New-Alias -Name gpn -Value Get-PSNews
New-Alias -Name ggt -Value Get-GoogleTranslate
New-Alias -Name gs -Value Get-Screenshot
New-Alias -Name ism -Value Invoke-SendModules

function New-WindowTitleClock {
if (-not(dir variable: | ? {$_.Name -eq 'WindowTitleClockTimer'}))
    {
        $global:WindowTitleClockTimer = New-Object System.Timers.Timer
        $global:WindowTitleClockTimer.Interval = 1000 #1 second
        $global:WindowTitleClockTimer.Enabled=$True
        $global:Action = {       
                    $Title = Get-CurrentDateDetailedInfo | Select-Object Day,DayOfWeek,Month,MonthName,FirstDayOfMonth,LastDayOfMonth,WeekInMonth,WeekInYear,Year,DayOfYear,DaysInYear,Hour,Minute,Second,Millisecond
                    $Host.UI.RawUI.WindowTitle = "$($Title.Hour):$($Title.Minute):$($Title.Second) | $($Title.Day) $($Title.DayOfWeek) $($Title.MonthName) ($($Title.Month)) $($Title.Year) | SoM $($Title.FirstDayOfMonth) EoM $($Title.LastDayOfMonth) | WiM $($Title.WeekInMonth) WiY $($Title.WeekInYear) DoY $($Title.DayOfYear) DiY $($Title.DaysInYear)"
                  } 
        [void](Register-ObjectEvent -InputObject $global:WindowTitleClockTimer -EventName elapsed -SourceIdentifier WindowTitleClockTimer -Action $Action)
    }
}
New-WindowTitleClock

function Remove-WindowTitleClock {
if (dir variable: | ? {$_.Name -eq 'WindowTitleClockTimer'})
    {
        Remove-Variable -Name 'WindowTitleClockTimer' -Scope Global -Force
        Stop-Job -Name WindowTitleClockTimer
        Remove-Job -Name WindowTitleClockTimer -Force
        $Host.UI.RawUI.WindowTitle = "Администратор: Windows PowerShell ISE"
    }
}

function Start-WindowTitleClock {
    if (dir variable: | ? {$_.Name -eq 'WindowTitleClockTimer'})
    {
        $global:WindowTitleClockTimer.Start()
    }
}

function Stop-WindowTitleClock {
    if (dir variable: | ? {$_.Name -eq 'WindowTitleClockTimer'})
    {
        $global:WindowTitleClockTimer.Stop()
    }
}
Start-WindowTitleClock

#Start-IisExpress -SiteName ps

if(!(Test-Path variable:KondorSybase))
{
    New-Variable -Name KondorSybase -Value @{ 
                                                'ServerName'      = ''
                                                'DSN'             = ''
                                                'Port'            = ''
                                                'DefaultDatabase' = ''
                                                'Login'           = ''
                                                'Password'        = ''
                                            }   `
                                    -Description "Kondor+ connection string" `
                                    -Option ReadOnly `
                                    -Scope "Global"
}
if(!(Test-Path variable:EmailSettings))
{
    New-Variable -Name EmailSettings -Value @{ 
                                                'SmtpServer' = 'smtp1.go.rshbank.ru'
                                                'To'         = 'PashkovKM@RSHB.ru'
                                                'From'       = 'PashkovKM@RSHB.ru'
                                                'Subject'    = 'Powershell automated email message'
                                                'Priority'   = 'High'
                                                'Encoding'   = [System.Text.Encoding]::UTF8
                                            }   `
                                    -Description "RSHB email settings" `
                                    -Option ReadOnly `
                                    -Scope "Global"
}
if(!(Test-Path variable:EmailSettingsYandex))
{
    New-Variable -Name EmailSettingsYandex -Value @{ 
                                                'SmtpServer' = 'smtp1.go.rshbank.ru'
                                                'To'         = 'KirillPashkov@yandex.ru'#,'PashkovKM@RSHB.ru',
                                                'From'       = 'PashkovKM@RSHB.ru'
                                                'Priority'   = 'High'
                                                'Encoding'   = [System.Text.Encoding]::UTF8
                                            }   `
                                    -Description "Yandex email settings" `
                                    -Option ReadOnly `
                                    -Scope "Global"
}

function Get-RSHB
{
param(
    [Parameter(Mandatory=$true,Position=0)][String]$Unit,
    [Parameter(Mandatory=$false,Position=1)][ValidateSet('go.rshbank.ru','rf.rshbank.ru','rshbintech.ru')][String]$Domain='rshbintech.ru',
    [Parameter(Mandatory=$false,Position=2)][String]$Filter='DisplayName'
)
    function Get-PDC
    {
        param($Domain)
        Get-ADDomainController -DomainName $Domain -Discover -ForceDiscover -Service PrimaryDC | Select -ExpandProperty HostName
    }
    try
    {
        $DC = Get-PDC -Domain $Domain
        $Value = $("*{0}*" -f $Unit)
        Get-ADUser -Server $DC -Filter {$Filter -like $Value} -Properties *
    }
    catch
    {
        $Error[0].Exception.Message
        break
    }
}

function relmod {
Remove-Module PK-Tools
Import-Module PK-Tools -Verbose
}

if ($Host.Name -eq 'Windows PowerShell ISE Host')
{
    if ($env:USERDOMAIN -eq 'RSHBINTECH')
    {[void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add('Send Module',{ism -ModuleName PK-Tools -Verbose},"F7"))} #RSHB

    if ($env:PSModulePath -split ";" | % {gci $_} | ? {$_.Name -eq 'ISERegex'})
    {[void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Start ISERegex",{Start-ISERegex},$Null))}

    if ($env:PSModulePath -split ";" | % {gci $_} | ? {$_.Name -eq 'AdvancedSearch'})
    {[void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Start Advanced Search",{Show-AdvancedSearchAddon},$Null))}

    [void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add('CB Rates Yesterday',{gry},$null))
    [void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add('CB Rates Tomorrow',{grt},$null))
    [void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add('CB Metal Rates',{gmr},$null))
    #[void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Convert Selected to Alias",{Convert-AliasDefinition $psise.CurrentFile.Editor.SelectedText -ToAlias},$Null)) #ISETools
    #[void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Convert Selected to Command",{Convert-AliasDefinition $psise.CurrentFile.Editor.SelectedText -ToDefinition},$Null)) #ISETools
    [void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Translate English to Russian",{ggt -TranslateFrom Английский -TranslateTo Русский -String $psise.CurrentFile.Editor.SelectedText},"F6"))
    [void]($psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Translate Russian to English",{ggt -TranslateFrom Русский -TranslateTo Английский -String $psise.CurrentFile.Editor.SelectedText},"Shift+F6"))
}
'@ | Out-File $file -Force
                Write-Verbose 'Mode UsePattern used'
            }
        }
    }
    else 
    {
        Write-Warning "$file not existing. Select -Mode New to create one and -Type to define type of profile."
    }
}

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

function Format-XML
{
  Param([string]$xml)
  $out = New-Object System.IO.StringWriter
  $Doc=New-Object system.xml.xmlDataDocument 
  $doc.LoadXml($xml) 
  $writer=New-Object system.xml.xmltextwriter($out) 
  $writer.Formatting = [System.xml.formatting]::Indented 
  $doc.WriteContentTo($writer) 
  $writer.Flush()
  $out.flush()
  Write-Output $out.ToString()
}

#variables

#aliases
New-Alias -Name isc -Value Invoke-SiebelSrvMgrCmd -Description 'Alias for Invoke-SiebelSrvMgrCmd function'
New-Alias -Name iss -Value Invoke-SQLServer -Description 'Alias for Invoke-SQLServer function'
New-Alias -Name isa -Value Invoke-SybaseASEQuery -Description 'Alias for Invoke-SybaseASEQuery function'

Export-ModuleMember -Function * -Alias *
