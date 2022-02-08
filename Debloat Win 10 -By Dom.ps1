# Backup point
# Disable (/Enable) Cortana
# Stop edge default PDF
# Appends an underscore '_' to the Registry key for Edge
# Disable Telemetry
# Disable Wi-Fi Sense
# Disable SmartScreen Filter
# Disable Application suggestions and automatic installation
# Disable Activity History feed in Task View OPTIONAL
# Disable sensor features, such as screen auto rotation
# Disable location feature and scripting for the location feature
# Disable automatic Maps updates
# Disable Feedback
# Disable Tailored Experiences
# Disable Advertising ID
# isable setting 'Let websites provide locally relevant content by accessing my language list'
# Disable Error reporting
# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
# Stop and disable Device Management Wireless Application Protocol (WAP) Push Service
# Enable clearing of recent files on exit
# Disable recent files lists
# Disable UWP apps background access - ie. if UWP apps can download data or update themselves when they aren't used
# Disable access to voice activation from UWP apps
# Disable access to notifications from UWP apps
# Disable access to account info from UWP app
# Disable access to contacts from UWP apps
# Disable access to calendar from UWP apps
# Disable access to phone calls from UWP apps
# Disable access to call history from UWP apps
# Disable access to email from UWP apps
# Disable access to tasks from UWP apps
# Disable access to messaging (SMS, MMS) from UWP apps
# Disable access to radios (e.g. Bluetooth) from UWP apps
# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
# Disable access to diagnostic information from UWP apps
# Disable access to libraries and file system from UWP apps
# Disable Hibernation
# Disable Sleep start menu and keyboard button
# Disable display and sleep mode timeouts
# Disable Fast Startup
# Uninstall some default Microsoft applications
# Uninstall default third party applications
# Disable Xbox features - Not applicable to Server OPTIONAL
# Disable Edge preload after Windows startup - Applicable since Win10 1809
# Disable Edge desktop shortcut creation after certain Windows updates are applied
# Disable Internet Explorer first run wizard
# Uninstall Internet Explorer
# Uninstall Windows Hello Face - Not applicable to Server
# Uninstall Windows Fax and Scan Services - Not applicable to Server
# Uninstall Microsoft XPS Document Writer
# Uninstall Microsoft Print to PDF


Write-Output "Debloat Custom by Dom"
Write-Output "Creando il punto di ripristino..."
Checkpoint-Computer -Description "Before Debloat" -RestorePointType MODIFY_SETTINGS
Write-Output "Punto di ripristino Creato!..."

    Write-Host "Disabling Cortana"
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
	If (!(Test-Path $Cortana1)) {
		New-Item $Cortana1
	}
	Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
	If (!(Test-Path $Cortana2)) {
		New-Item $Cortana2
	}
	Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
	Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
	If (!(Test-Path $Cortana3)) {
		New-Item $Cortana3
	}
	Set-ItemProperty $Cortana3 HarvestContacts -Value 0

# Enable Cortana 
#
# Write-Host "Re-enabling Cortana"
#     $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
#     $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
#     $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
# 	If (!(Test-Path $Cortana1)) {
# 		New-Item $Cortana1
# 	}
# 	Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 1 
# 	If (!(Test-Path $Cortana2)) {
# 		New-Item $Cortana2
# 	}
# 	Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 0 
# 	Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 0 
# 	If (!(Test-Path $Cortana3)) {
# 		New-Item $Cortana3
# 	}
# 	Set-ItemProperty $Cortana3 HarvestContacts -Value 1 
#

# Stops edge from taking over as the default .PDF viewer    
Write-Output "Stopping Edge from taking over as the default .PDF viewer"
$NoPDF = "HKCR:\.pdf"
$NoProgids = "HKCR:\.pdf\OpenWithProgids"
$NoWithList = "HKCR:\.pdf\OpenWithList" 
If (!(Get-ItemProperty $NoPDF  NoOpenWith)) {
    New-ItemProperty $NoPDF NoOpenWith 
}        
If (!(Get-ItemProperty $NoPDF  NoStaticDefaultVerb)) {
    New-ItemProperty $NoPDF  NoStaticDefaultVerb 
}        
If (!(Get-ItemProperty $NoProgids  NoOpenWith)) {
    New-ItemProperty $NoProgids  NoOpenWith 
}        
If (!(Get-ItemProperty $NoProgids  NoStaticDefaultVerb)) {
    New-ItemProperty $NoProgids  NoStaticDefaultVerb 
}        
If (!(Get-ItemProperty $NoWithList  NoOpenWith)) {
    New-ItemProperty $NoWithList  NoOpenWith
}        
If (!(Get-ItemProperty $NoWithList  NoStaticDefaultVerb)) {
    New-ItemProperty $NoWithList  NoStaticDefaultVerb 
}
        
#Appends an underscore '_' to the Registry key for Edge
$Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
If (Test-Path $Edge) {
    Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ 
}

# Enable edge for PDF
Write-Output "Setting Edge back to default"
    $NoPDF = "HKCR:\.pdf"
    $NoProgids = "HKCR:\.pdf\OpenWithProgids"
    $NoWithList = "HKCR:\.pdf\OpenWithList"
    #Sets edge back to default
    If (Get-ItemProperty $NoPDF  NoOpenWith) {
        Remove-ItemProperty $NoPDF  NoOpenWith
    } 
    If (Get-ItemProperty $NoPDF  NoStaticDefaultVerb) {
        Remove-ItemProperty $NoPDF  NoStaticDefaultVerb 
    }       
    If (Get-ItemProperty $NoProgids  NoOpenWith) {
        Remove-ItemProperty $NoProgids  NoOpenWith 
    }        
    If (Get-ItemProperty $NoProgids  NoStaticDefaultVerb) {
        Remove-ItemProperty $NoProgids  NoStaticDefaultVerb 
    }        
    If (Get-ItemProperty $NoWithList  NoOpenWith) {
        Remove-ItemProperty $NoWithList  NoOpenWith
    }    
    If (Get-ItemProperty $NoWithList  NoStaticDefaultVerb) {
        Remove-ItemProperty $NoWithList  NoStaticDefaultVerb
    }
        
    #Removes an underscore '_' from the Registry key for Edge
    $Edge2 = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
    If (Test-Path $Edge2) {
        Set-Item $Edge2 AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723
    }

# Disable Telemetry
# Note: This tweak also disables the possibility to join Windows Insider Program and breaks Microsoft Intune enrollment/deployment, as these feaures require Telemetry data.
# Windows Update control panel may show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again.
# See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57 and https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/92

Write-Output "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
# Office 2016 / 2019
Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null

# Disable Wi-Fi Sense
Write-Output "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0

# Disable SmartScreen Filter

Write-Output "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0

# Disable Application suggestions and automatic installation

Write-Output "Disabling Application suggestions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
    $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
    Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
    Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
}

# Disable Activity History feed in Task View OPTIONAL
# Note: The checkbox "Store my activity history on this device" ("Let Windows collect my activities from this PC" on older versions) remains checked even when the function is disabled

# Write-Output "Disabling Activity History..."
# 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
# 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
# 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

# Disable sensor features, such as screen auto rotation

Write-Output "Disabling sensors..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1

# Disable location feature and scripting for the location feature

Write-Output "Disabling location services..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1

# Disable automatic Maps updates

Write-Output "Disabling automatic Maps updates..."
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

# Disable Feedback

Write-Output "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

# Disable Tailored Experiences

Write-Output "Disabling Tailored Experiences..."
If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

# Disable Advertising ID

Write-Output "Disabling Advertising ID..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

# isable setting 'Let websites provide locally relevant content by accessing my language list'

Write-Output "Disabling Website Access to Language List..."
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1

# Disable Error reporting

Write-Output "Disabling Error reporting..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled

# Stop and disable Device Management Wireless Application Protocol (WAP) Push Service
# Note: This service is needed for Microsoft Intune interoperability

Write-Output "Stopping and disabling Device Management WAP Push Service..."
Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
Set-Service "dmwappushservice" -StartupType Disabled

# Enable clearing of recent files on exit
# Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.

Write-Output "Enabling clearing of recent files on exit..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1

# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.

Write-Output "Disabling recent files lists..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1

# Disable UWP apps background access - ie. if UWP apps can download data or update themselves when they aren't used
# Until 1809, Cortana and ShellExperienceHost need to be explicitly excluded as their inclusion breaks start menu search and toast notifications respectively.

Write-Output "Disabling UWP apps background access..."
If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
} Else {
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
}


# Disable access to voice activation from UWP apps

Write-Output "Disabling access to voice activation from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2

# Disable access to notifications from UWP apps

Write-Output "Disabling access to notifications from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2

# Disable access to account info from UWP app
Write-Output "Disabling access to account info from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2

# Disable access to contacts from UWP apps

Write-Output "Disabling access to contacts from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2

# Disable access to calendar from UWP apps

Write-Output "Disabling access to calendar from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2

# Disable access to phone calls from UWP apps

Write-Output "Disabling access to phone calls from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2

# Disable access to call history from UWP apps

Write-Output "Disabling access to call history from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2

# Disable access to email from UWP apps

Write-Output "Disabling access to email from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2

# Disable access to tasks from UWP apps
Write-Output "Disabling access to tasks from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2

# Disable access to messaging (SMS, MMS) from UWP apps

Write-Output "Disabling access to messaging from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2

# Disable access to radios (e.g. Bluetooth) from UWP apps

Write-Output "Disabling access to radios from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2

# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
Write-Output "Disabling access to other devices from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2

# Disable access to diagnostic information from UWP apps
Write-Output "Disabling access to diagnostic information from UWP apps..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2

# Disable access to libraries and file system from UWP apps

Write-Output "Disabling access to libraries and file system from UWP apps..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny"

# Disable Hibernation

Write-Output "Disabling Hibernation..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
powercfg /HIBERNATE OFF 2>&1 | Out-Null

# Disable Sleep start menu and keyboard button

Write-Output "Disabling Sleep start menu and keyboard button..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0

# Disable display and sleep mode timeouts

Write-Output "Disabling display and sleep mode timeouts..."
powercfg /X monitor-timeout-ac 0
powercfg /X monitor-timeout-dc 0
powercfg /X standby-timeout-ac 0
powercfg /X standby-timeout-dc 0

# Disable Fast Startup

Write-Output "Disabling Fast Startup..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

# Uninstall default Microsoft applications

Write-Output "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.HelpAndTips" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Media.PlayReadyClient.2" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Reader" | Remove-AppxPackage
Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WinJS.1.0" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WinJS.2.0" | Remove-AppxPackage
Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather

# Uninstall default third party applications

Write-Output "Uninstalling default third party applications..."
Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage
Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage
Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage
Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage
Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage
Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage
Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage
Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage
Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage
Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage

# Disable Xbox features - Not applicable to Server OPTIONAL

# Write-Output "Disabling Xbox features..."
# Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
# Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
# If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
#     New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
# }
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

# Disable Edge preload after Windows startup - Applicable since Win10 1809

Write-Output "Disabling Edge preload..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0

# Disable Edge desktop shortcut creation after certain Windows updates are applied

Write-Output "Disabling Edge shortcut creation..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1

# Disable Internet Explorer first run wizard

Write-Output "Disabling Internet Explorer first run wizard..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1

# Uninstall Internet Explorer

Write-Output "Uninstalling Internet Explorer..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null

# Uninstall Work Folders Client - Not applicable to Server
Write-Output "Uninstalling Work Folders Client..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null

# Uninstall Windows Hello Face - Not applicable to Server

Write-Output "Uninstalling Windows Hello Face..."
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Hello.Face*" } | Remove-WindowsCapability -Online | Out-Null
# Uninstall Windows Fax and Scan Services - Not applicable to Server

Write-Output "Uninstalling Windows Fax and Scan Services..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
# Uninstall Microsoft XPS Document Writer

Write-Output "Uninstalling Microsoft XPS Document Writer..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
# Uninstall Microsoft Print to PDF

Write-Output "Uninstalling Microsoft Print to PDF..."
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null