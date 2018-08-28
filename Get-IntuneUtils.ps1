function Get-AuthToken {

    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
    if ($AadModule -eq $null) {
    
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    }
    
    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
    if ($AadModule.count -gt 1) {
    
        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
        # Checking if there are multiple versions of the same module found
    
        if ($AadModule.count -gt 1) {
    
            $aadModule = $AadModule | select -Unique
    
        }
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    else {
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = ""
    
    $redirectUri = ""
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
    try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
        # If the accesstoken is valid then create the authentication header
    
        if ($authResult.AccessToken) {
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
    
            return $authHeader
    
        }
    
        else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
    }
    
}

$authToken = Get-AuthToken -User "byk@atp.dk"

Function Get-AADUser() {

    
    [cmdletbinding()]
    
    param
    (
        $userPrincipalName,
        $Property
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $User_resource = "users"
    
    try {
    
        if ($userPrincipalName -eq "" -or $userPrincipalName -eq $null) {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
        }
    
        else {
    
            if ($Property -eq "" -or $Property -eq $null) {
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
                Write-Verbose $uri
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
    
            else {
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
                Write-Verbose $uri
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
    
####################################################
    
Function Get-AADUserDevices() {
    

    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "UserID (guid) for the user you want to take action on must be specified:")]
        $UserID
    )
    
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "users/$UserID/managedDevices"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Write-Verbose $uri
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
    
Function Get-DepDevices() {
    

    [cmdletbinding()]
    
    param
    (
    )
    
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/importedAppleDeviceIdentities"
    
    try {
    
        # $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $uri = "https://graph.microsoft.com/beta/deviceManagement/importedAppleDeviceIdentities"
        Write-Verbose $uri
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
    
Function Invoke-DeviceAction() {
    
    [cmdletbinding()]
    
    param
    (
        [switch]$RemoteLock,
        [switch]$ResetPasscode,
        [switch]$Wipe,
        [switch]$Retire,
        [switch]$Delete,
        [switch]$Sync,
        [Parameter(Mandatory = $true, HelpMessage = "DeviceId (guid) for the Device you want to take action on must be specified:")]
        $DeviceID
    )
    
    $graphApiVersion = "Beta"
    
    try {
    
        $Count_Params = 0
    
        if ($RemoteLock.IsPresent) { $Count_Params++ }
        if ($ResetPasscode.IsPresent) { $Count_Params++ }
        if ($Wipe.IsPresent) { $Count_Params++ }
        if ($Retire.IsPresent) { $Count_Params++ }
        if ($Delete.IsPresent) { $Count_Params++ }
        if ($Sync.IsPresent) { $Count_Params++ }
    
        if ($Count_Params -eq 0) {
    
            write-host "No parameter set, specify -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red
    
        }
    
        elseif ($Count_Params -gt 1) {
    
            write-host "Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red
    
        }
    
        elseif ($RemoteLock) {
    
            $Resource = "deviceManagement/managedDevices/$DeviceID/remoteLock"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending remoteLock command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
    
        }
    
        elseif ($ResetPasscode) {
    
            write-host
            write-host "Are you sure you want to reset the Passcode this device? Y or N?"
            $Confirm = read-host
    
            if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
                $Resource = "deviceManagement/managedDevices/$DeviceID/resetPasscode"
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
                write-verbose $uri
                Write-Verbose "Sending remotePasscode command to $DeviceID"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
    
            }
    
            else {
    
                Write-Host "Reset of the Passcode for the device $DeviceID was cancelled..."
    
            }
    
        }
    
        elseif ($Wipe) {
    
            write-host
            write-host "Are you sure you want to wipe this device? Y or N?"
            $Confirm = read-host
    
            if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
                $Resource = "deviceManagement/managedDevices/$DeviceID/wipe"
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
                write-verbose $uri
                Write-Verbose "Sending wipe command to $DeviceID"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
    
            }
    
            else {
    
                Write-Host "Wipe of the device $DeviceID was cancelled..."
    
            }
    
        }
    
        elseif ($Retire) {
    
            write-host
            write-host "Are you sure you want to retire this device? Y or N?"
            $Confirm = read-host
    
            if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
                $Resource = "deviceManagement/managedDevices/$DeviceID/retire"
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
                write-verbose $uri
                Write-Verbose "Sending retire command to $DeviceID"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
    
            }
    
            else {
    
                Write-Host "Retire of the device $DeviceID was cancelled..."
    
            }
    
        }
    
        elseif ($Delete) {
    
            write-host
            Write-Warning "A deletion of a device will only work if the device has already had a retire or wipe request sent to the device..."
            Write-Host
            write-host "Are you sure you want to delete this device? Y or N?"
            $Confirm = read-host
    
            if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
                $Resource = "deviceManagement/managedDevices('$DeviceID')"
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
                write-verbose $uri
                Write-Verbose "Sending delete command to $DeviceID"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
    
            }
    
            else {
    
                Write-Host "Deletion of the device $DeviceID was cancelled..."
    
            }
    
        }
            
        elseif ($Sync) {
    
            write-host
            write-host "Are you sure you want to sync this device? Y or N?"
            $Confirm = read-host
    
            if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
                $Resource = "deviceManagement/managedDevices('$DeviceID')/syncDevice"
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
                write-verbose $uri
                Write-Verbose "Sending sync command to $DeviceID"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
    
            }
    
            else {
    
                Write-Host "Sync of the device $DeviceID was cancelled..."
    
            }
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
