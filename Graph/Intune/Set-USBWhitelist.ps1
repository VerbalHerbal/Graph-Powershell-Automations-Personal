<#
.SYNOPSIS
    Intune USB Policy Updater and Defender Audit Tracker

.DESCRIPTION
    This script fetches, parses, and updates an Intune Device Configuration Policy (USB whitelist).
    It also queries Defender via Microsoft Graph Security API to audit past USB mount events based on serial numbers.

.NOTES
    Replace all <PLACEHOLDER> values with your tenant-specific settings.
    Author: Your Name
    License: MIT
#>

# --------------------------------------
# USER CONFIGURABLE VARIABLES
# --------------------------------------

# Input list of USB identifiers
#$inputStrings = "USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER_GLIDE&REV_1.00\\0000000000000000&0"

# Export file naming
$date = Get-Date -Format "yyyy-MMMM-dd"
$fileNameBackup = "Group-Approved USBs_$($date)_<username>_workUSB_backup.xml"
$fileNameExport = "Group-Approved USBs_$($date)_<username>_workUSB_export.xml"
$exportPathBackup = ".\Output\$fileNameBackup"
$exportPathExport = ".\Output\$fileNameExport"

# Device Configuration Policy ID
$deviceConfigurationId = "<DeviceConfigurationId>"

# GRAPH AUTH CONFIGURATION
$mgContext = Get-MgContext
if ($mgContext.AppName -ne "<AppName>") {
    $CertThumbprint = "<CertificateThumbprint>"
    $TenantId = "<TenantId>"
    $ClientId = "<ClientId>"
    Connect-MgGraph -CertificateThumbprint $CertThumbprint -TenantId $TenantId -ClientId $ClientId -NoWelcome
}

###########################################################
#    Get the current configuration and backup the XML     #
###########################################################

# Fetch current configuration
$config = Get-MgBetaDeviceManagementDeviceConfiguration -DeviceConfigurationId $deviceConfigurationId
$usbOma = $config.additionalProperties.omaSettings | Where-Object {$_.displayName -eq "<AllowedUsbPolicyDisplayName>"}
$secretReferenceValueId = $usbOma.secretReferenceValueId

# Get the current XML configuration in plaintext
$graph = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$deviceConfigurationId/getOmaSettingPlainTextValue(secretReferenceValueId='$($secretReferenceValueId)')" 
$omaSettings = $graph."value"
$xmlGraph = [xml]$omaSettings
$xmlGraphInstancePathId = $xmlGraph.Group.DescriptorIdList.InstancePathId

# Export the XML for backup
$date = Get-Date -Format "yyyy-MMMM-dd"
$fileNameBackup = "Group-Approved USBs_$($date)_$($env:USERNAME)_workUSB_backup.xml"
$xmlGraph.Save($exportPathBackup)

#######################################################################
# Parse the XML and extract the relevant information for the new entry #
#######################################################################

$SerializedPaths = New-Object System.Collections.ArrayList
foreach ($line in $inputStrings) {

    if ($line -like "USBSTOR*") {
        # Check if line has "REV_\" directly (with no chars in between)
        if ($line -like "*REV_\*") {
            # Pattern for lines where REV_ is followed directly by a backslash
            $serial = [regex]::match($line, '(?<=REV_\\)[^&]+').Value
        } else {
            # Pattern for lines where there's something between REV_ and the final backslash
            $serial = [regex]::match($line, '(?<=REV_[^\\]+\\)[^&]+').Value
        }

        if ($serial -and $serial.Length -eq 1) {
            # Try extracting the portion after REV_ and the backslash
            $postRev = [regex]::Match($line, '(?<=REV_[^\\]*\\).*').Value
            $serial = ($postRev -split '&')[1]
        }
        $global:partsSplit = ($line -split '&') -split '\\'

    } elseif ($line -like "SCSI*") {
        # SCSI handling remains the same
        $parts = $line -split '\\', 2
        $subparts = $parts[1] -split '&'
        # Adjust index if needed based on the actual pattern
        $serial = $subparts[3]
        $global:partsSplit = ($line -split '&') -split '\\'
        $patternSCSISingleDigit = '(?<=[\\])\d(?=&)' # Pattern for single-digit number between "\" and "&" characters in SCSI lines
        $line = [regex]::Replace($line, $patternSCSISingleDigit, '*')
    }
    else {
        $serial = $null
    }

    $SingleDigit = $partsSplit | Where-Object {$_.Length -eq 1}
    if ($SingleDigit.Count -eq 1) {
        $PortNumber = $SingleDigit
    } elseif ($SingleDigit.Count -gt 1) {
        $PortNumber = $SingleDigit[-1]

    } elseif ($SingleDigit.Count -eq 0) {
        #$PortNumber = $serial[-1]
        $PortNumber = $null
    }
    # Replace the PortNumber with a wildcard in the line
    $pattern = "(?<=(&|\\))" + [regex]::Escape($PortNumber) + "(?=(&|\\)|$)"
    $lineWithWildcard = [regex]::Replace($Line, $pattern, "*")

    $FinalizedLine = ("<InstancePathId>$lineWithWildcard</InstancePathId>" -replace '&','&amp;')
    
    $SerializedObject = [PSCustomObject]@{
        Line = $line
        SerialNumber = $serial
        Product = if ($partsSplit) {$partsSplit[3]} else {''}
        Vendor = if ($partsSplit) {$partsSplit[2]} else {''}
        DriveType = if ($partsSplit) {$partsSplit[1]} else {''}
        BusType = if ($partsSplit) {$partsSplit[0]} else {''}
        PartsCount = $global:partsSplit.Count
        PortNumber = $PortNumber
        SerialLength = [int]$serial.Length
        SingleDigitStringCount = $SingleDigit.Count
        FinalizedLine = $FinalizedLine
    }
    $SerializedPaths.Add($SerializedObject) | Out-Null
    
    # Check if the entry already exists in the configuration based on the SerialNumber, Product, Vendor, and BusType
    $DuplicateLookup = $xmlGraphInstancePathId | Where-Object {$_ -like "*$($SerializedObject.SerialNumber)*" -and $_ -like "*$($SerializedObject.Product)*" -and $_ -like "*$($SerializedObject.Vendor)*" -and $_ -like "*$($SerializedObject.BusType)*"} 

    if ($DuplicateLookup) {
        Write-Error "Entry $DuplicateLookup already exists in the configuration"
        # Remove the entry from the list
        $SerializedPaths.Remove($SerializedObject) | Out-Null
        Continue
    } 

    # Validate the string
    $validString = $SerializedObject | Where-Object {
        (($_.SerialNumber.Length -gt 1) -and $_.Product -and $_.Vendor -and $_.BusType) -and `
        ($_.Product -like "PROD_*" -or $_.Vendor -like "VEN_*") -and `
        !($_.Line -match "\s") # No whitespace allowed
    } 

    if (!$validString) {
        Write-Error "Invalid strings found in the input: $($SerializedObject.Line)"
        # skip the entry
        $SerializedPaths.Remove($SerializedObject) | Out-Null
        Continue
    }

}
if (!$SerializedPaths) {
    Write-Error "No valid entries found in the input"
    exit 1
}

# $SerializedPaths  | Out-GridView #| Group-Object -Property PortNumberIndex | Sort-Object -Property Count -Descending




########################################
#   Monitoring Flow for Defender API   #
########################################

# Construct the KQL query

if ($SerializedPaths.Count -gt 10) {
    # Split the serial numbers into chunks of 40 for the KQL query
    $chunks = [System.Collections.ArrayList]@()
    # Perform math to get the number of chunks
    $chunkCount = [math]::Ceiling($SerializedPaths.Count / 10)
    for ($i = 0; $i -lt $chunkCount; $i++) {
        $start = $i * 10
        $end = $start + 10
        $chunks.Add($SerializedPaths[$start..($end - 1)])
    }
} else {
    $chunks = [System.Collections.ArrayList]@($SerializedPaths)
}


$chunksArray = New-Object System.Collections.ArrayList
foreach ($chunk in $chunks) {
    $serialNumbersKQL = $chunk.SerialNumber -join '","'
    # Construct the KQL query to search Defender for logs related to the serial numbers
    $query = @"
DeviceEvents
| where Timestamp >= ago(180d)
| where ActionType in ("AsrUntrustedUsbProcessAudited", 
"AsrUntrustedUsbProcessWarnBypassed", 
"UsbDriveMount", 
"UsbDriveMounted", 
"UsbDriveUnmount",
"RemovableStoragePolicyTriggered")
| extend AdditionalFieldsParsed = parse_json(AdditionalFields)
| extend DeviceInstanceId = tostring(AdditionalFieldsParsed.DeviceInstanceId), SerialNumber = tostring(AdditionalFieldsParsed.SerialNumber)
| where AdditionalFieldsParsed has_any (dynamic(["$serialNumbersKQL"]))
| summarize arg_max(Timestamp, *) by coalesce(DeviceInstanceId, SerialNumber)
| project 
    DeviceName, 
    DeviceId, 
    Timestamp, 
    InitiatingProcessAccountName, 
    ActionType, 
    RemovableStoragePolicyVerdict = tostring(AdditionalFieldsParsed.RemovableStoragePolicyVerdict), 
    DeviceInstanceId, 
    RemovableStoragePolicy = tostring(AdditionalFieldsParsed.RemovableStoragePolicy), 
    SerialNumber
"@

    # Define the parameters
    $params = @{
        Query = $query
    }

    #$hunt = Start-MgBetaSecurityHuntingQuery -BodyParameter $params
    $huntQuery = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/runHuntingQuery" -Body $params # Has a hard limit for timeout after 300 seconds

    if ($huntQuery){ 
        $chunksArray.Add($huntQuery.results)
    }
}

Write-Host "Defender API query has been executed successfully. Found the following matches:" -ForegroundColor Yellow
foreach ($object in $SerializedPaths) {
    
    $huntQuery.results | Where-Object {$_."SerialNumber" -eq $object.SerialNumber -or $object.SerialNumber -in $_."AdditionalFieldsParsed"}

    # If the entry is valid and not a duplicate, add it to the XML
    $parentNode = $xmlGraph.SelectSingleNode('//DescriptorIdList')
    if (-not $parentNode) {
        Write-Warning "Could not find a <DescriptorIdList> node."
        $parentNode = $xmlGraph.DocumentElement  # fallback if needed
    }
    [xml]$newXmlBlock = $object.FinalizedLine
    $newNode = $xmlGraph.ImportNode($newXmlBlock.DocumentElement, $true)
    $parentNode.AppendChild($newNode) | Out-Null
}

########################################
# Prepare the XML to Base64 for Intune #
########################################

# Create a memory stream
$memStream = New-Object System.IO.MemoryStream

# Configure XmlWriterSettings
$xmlWriterSettings = New-Object System.Xml.XmlWriterSettings
$xmlWriterSettings.Encoding = New-Object System.Text.UTF8Encoding($false)  # UTF-8 without BOM
$xmlWriterSettings.Indent = $true
$xmlWriterSettings.IndentChars = ' ' * 4  # Optional: set indentation to 4 spaces
$xmlWriterSettings.OmitXmlDeclaration = $true  # Omit the XML declaration
$xmlWriterSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document  # Set to Document

# Create an XmlWriter with the specified settings
$xmlWriter = [System.Xml.XmlWriter]::Create($memStream, $xmlWriterSettings)

# Write (save) the XML content into the writer
$xmlGraph.Save($xmlWriter)
$xmlWriter.Flush()
$memStream.Position = 0

# Read the memory stream back as a string
$reader = New-Object System.IO.StreamReader($memStream, $xmlWriterSettings.Encoding)
$formattedXml = $reader.ReadToEnd()

# Close resources
$reader.Close()
$xmlWriter.Close()

# Save the formatted XML to a file for export backup
[System.IO.File]::WriteAllText($exportPathExport, $formattedXml, $xmlWriterSettings.Encoding)


# Convert the XML content to Base64
$encodedXml = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($formattedXml))
# Update the configuration in Intune

$omaObjects = @{}
$omaSettings = foreach ($setting in $config.additionalProperties.omaSettings) {
    if ($setting.secretReferenceValueId) {
        $omaValue = Get-MgBetaDeviceManagementDeviceConfigurationOmaSettingPlainTextValue -DeviceConfigurationId $deviceConfigurationId -SecretReferenceValueId $setting.secretReferenceValueId
    } else {
        $omaValue = $null
    }
    $omaObject = @{}
    # This has to be the schema for the script, as otherwise only the Allowed USB setting will be updated and the rest will be removed
    if ($setting.displayName -eq "<AllowedUsbPolicyDisplayName>") {
        $omaObject["$($setting.displayName)"] = [pscustomobject]@{
            "@odata.type"          = $setting."@odata.type"
            displayName            = $setting.displayName
            omaUri                 = $setting.omaUri
            secretReferenceValueId = $setting.secretReferenceValueId
            isEncrypted            = $setting.isEncrypted
            fileName               = $fileNameExport
            value                  = $omaValue.value
            encodedValue           = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($omaValue.value))
            newValue               = $formattedXml
            encodedNewValue        = $encodedXml
        }
    }
    elseif ($setting."@odata.type" -eq "#microsoft.graph.omaSettingStringXml") {
        $omaObject["$($setting.displayName)"] = [pscustomobject]@{
            "@odata.type"          = $setting."@odata.type"
            displayName            = $setting.displayName
            omaUri                 = $setting.omaUri
            secretReferenceValueId = $setting.secretReferenceValueId
            isEncrypted            = $setting.isEncrypted
            fileName               = $setting.fileName
            value                  = $omaValue.value
            encodedValue           = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($omaValue.value))
        }
    }
    elseif ($setting."@odata.type" -eq "#microsoft.graph.omaSettingInteger") {
        $omaObject["$($setting.displayName)"] = [pscustomobject]@{
            "@odata.type"          = $setting."@odata.type"
            displayName            = $setting.displayName
            omaUri                 = $setting.omaUri
            isEncrypted            = $setting.isEncrypted
            value                  = $setting.value
            isReadOnly             = $setting.isReadOnly
        }
    }

    $omaObjects += $omaObject
}

# Modify the configuration to build the body according to the required schema
$omaObjects."<AllowedUsbPolicyDisplayName>".value = $omaObjects."<AllowedUsbPolicyDisplayName>".encodedNewValue
$omaObjects."<AuditUsbPolicyDisplayName>".value   = $omaObjects."<AuditUsbPolicyDisplayName>".encodedValue
$omaObjects."<AllMediaPolicyDisplayName>".value   = $omaObjects."<AllMediaPolicyDisplayName>".encodedValue

$omaObjectsAllowedUsbExcluded = $omaObjects."<AllowedUsbPolicyDisplayName>" | Select-Object -ExcludeProperty encodedNewValue, encodedValue, newValue
$omaObjectsAuditWriteExcluded = $omaObjects."<AuditUsbPolicyDisplayName>" | Select-Object -ExcludeProperty encodedNewValue, encodedValue, newValue
$omaObjectsAllMediaExcluded    = $omaObjects."<AllMediaPolicyDisplayName>" | Select-Object -ExcludeProperty encodedNewValue, encodedValue, newValue
$omaObjectsEnableCustomFeature = $omaObjects."<EnableFeaturePolicyDisplayName>"


$paramsConfig = @{
	id = $deviceConfigurationId
	displayName = $config.displayName
    "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
    roleScopeTagIds = $config.roleScopeTagIds

    omaSettings = @(   
        $omaObjectsAllowedUsbExcluded,
        $omaObjectsAuditWriteExcluded,
        $omaObjectsAllMediaExcluded,
        $omaObjectsEnableCustomFeature
     )
}
$paramsConfigConvert = $paramsConfig | ConvertTo-Json | ConvertFrom-Json -AsHashtable

# Ask user to confirm before updating the configuration, provide the option to cancel and provide the string that will be added
Write-Host "The following string will be added to the configuration:" -ForegroundColor Yellow
$SerializedPaths | Select-Object -Property BusType, DriveType, Vendor, Product, SerialNumber, Line, FinalizedLine | Format-Table -AutoSize -Wrap

$title    = 'Updating Intune USB Control Policy'
$question = "WARNING: This operation will update the Intune USB Control Policy with the new entry. Do you want to proceed?
Confirm the string before proceeding."
$choices  = '&Yes', '&No'
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)

switch ($decision) {
    0 { Update-MgBetaDeviceManagementDeviceConfiguration -DeviceConfigurationId $deviceConfigurationId -BodyParameter $paramsConfigConvert }
    1 {
        Write-Host "`n"
        Write-Error 'User declined to continue, exiting'
        exit 1
    }
}

########## Confirm if the configuration has been updated correctly ##########

# Get the current configuration
$config = Get-MgBetaDeviceManagementDeviceConfiguration -DeviceConfigurationId $deviceConfigurationId
$allowedUsbOma = $config.additionalProperties.omaSettings | Where-Object {$_.displayName -eq "Allowed USB"}
$secretReferenceValueId = $allowedUsbOma.secretReferenceValueId
# Get the current XML configuration in plaintext
$graph = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$deviceConfigurationId/getOmaSettingPlainTextValue(secretReferenceValueId='$($secretReferenceValueId)')" 
$omaSettings = $graph."value"
$xmlGraph = [xml]$omaSettings
$xmlGraphInstancePathId = $xmlGraph.Group.DescriptorIdList.InstancePathId

# Check if the entry already exists in the configuration based on the SerialNumber, Product, Vendor, and BusType
$DuplicateLookup = foreach ($SerializedObject in $SerializedPaths) {
    $DuplicateEntry = $xmlGraphInstancePathId | Where-Object {$_ -like "*$($SerializedObject.SerialNumber)*" -and $_ -like "*$($SerializedObject.Product)*" -and $_ -like "*$($SerializedObject.Vendor)*" -and $_ -like "*$($SerializedObject.BusType)*"}

    if ($DuplicateEntry) {
        Write-Host "Entry $DuplicateEntry has been successfully added to the configuration" -ForegroundColor Green
    } else {
        Write-Error "Entry $($SerializedObject.FinalizedLine) was not found in the configuration"
    }
}
