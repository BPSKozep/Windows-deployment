# Post Setup script for windows laptop deployments in BPS (V2, without double boot)

# Steps:
#  1: Start powerhell, check for admin rights
#  2: Request required tokens from DC
#  3: Get machine BPS number from serial number or fallback to input
#  4: Delete old machine from Tailscale and Active Directory
#  5: Download and install Tailscale
#  6: Connect to Tailnet
#  7: Change IP based on BPS number
#  8: Join Active Directory and restart
$ErrorActionPreference = "Stop"

$SecondsRunning = 0
Write-Host "Press any key to start the script" -ForegroundColor Blue
while (-not ($Host.UI.RawUI.KeyAvailable) -and ($SecondsRunning -lt 70)) {
    Start-Sleep 1
    $SecondsRunning++
}

try {
    Write-Host "Welcome to BPS Post setup script V2 (Now with extensive color coding!)"  -ForegroundColor Magenta
    ""
    "--- Step 1: Start powerhell, check for admin rights ---"
    ""
    $isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')
    if (-not $isAdmin) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
        exit
    }
    Write-Host "Admin rights - OK" -ForegroundColor Green

    ""
    "--- Step 2: Request required tokens from DC ---"
    ""

    #Get serial from BIOS
    $serialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    Write-Host "Serial number - OK: $serialNumber" -ForegroundColor Green
    Start-Sleep 1
    # Powershell Universal token is lifetime
    $PUToken = Invoke-RestMethod "https://pu.bpskozep.hu/deployment/get-token/$serialNumber"
    if ($PUToken -ieq "you and token bad go away :(") {
        Write-Host "Wrong serial!" -ForegroundColor Red
        Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit

    }
    Write-Host "Powershell Universal - OK" -ForegroundColor Green
    # Tailscale token is requested from DC
    $tsAuthKey = Invoke-RestMethod -Uri "https://pu.bpskozep.hu/deployment/ts-auth/" -Method Post -Headers @{"Authorization" = "Bearer $PUToken" }
    Write-Host "Tailscale Authkey - OK" -ForegroundColor Green

    ""
    "--- Step 3: Get machine BPS number from serial number or fallback to input ---"
    ""


    # Match serial with bpsnumber from DC
    $bpsNumber = Invoke-RestMethod -Uri "https://pu.bpskozep.hu/deployment/serial-to-bps/$serialNumber" -Headers @{"Authorization" = "Bearer $PUToken" }
    Write-Host "BPS number - OK: $bpsNumber" -ForegroundColor Green

    # If serial returned nothing, fallback input
    if ([string]::IsNullOrEmpty($bpsNumber)) {
        $bpsNumber = Read-Host "No serial entry found, enter the BPS number"
        $newComputerName = "BPS-$bpsNumber"
    }

    $newComputerName = "BPS-$bpsNumber"
    Write-Host "Computer name - OK: $newComputerName" -ForegroundColor Green  

    ""
    "--- Step 4: Delete old machine from Tailscale and Active Directory ---"
    ""

    #Send request to DC
    Invoke-RestMethod -Uri "https://pu.bpskozep.hu/deployment/delete/$newComputerName" -Method Post -Headers @{"Authorization" = "Bearer $PUToken" }

    try {
    (Get-Command "C:\Program Files\Tailscale\tailscale.exe" -ErrorAction Stop) *>$null
        Write-Host "Installing TS - Already installed, skipping" -ForegroundColor Blue
    }
    catch {

        ""
        "--- Step 5: Download and install Tailscale ---"
        ""

        $workdir = "C:\Windows\Temp"

        $TSDownloadUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"
        $TSDownloadPath = "$workdir\tailscale-setup-latest.msi"
        Invoke-WebRequest -Uri $TSDownloadUrl -OutFile $TSDownloadPath

        if (-not (Test-Path $TSDownloadPath)) {
            Write-Host "Downloading TS - Failed" -ForegroundColor Red
            Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            exit
        }

        Write-Host "Downloading TS - OK" -ForegroundColor Green

        Start-Process -FilePath "$workdir\tailscale-setup-latest.msi" -ArgumentList "-q" -Wait

        Start-Sleep 5

        # Try statement to check if TS is really installed
        try {
    (Get-Command "C:\Program Files\Tailscale\tailscale.exe" -ErrorAction Stop) *>$null
            Write-Host "Installing TS - OK" -ForegroundColor Green
        }
        catch {
            Write-Host "Installing TS - Failed" -ForegroundColor Red
            Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            exit
        }

    }

    ""
    "--- Step 6: Connect to Tailnet ---"
    ""

    # Start tailscale with authkey
    Start-Process "C:\Program Files\Tailscale\tailscale.exe" -ArgumentList "up", "--authkey", $tsAuthKey, "--unattended"

    Start-Sleep -Seconds 10

    try {
        # Ping the dc machine using Test-Connection cmdlet
        Test-Connection -ComputerName "dc" -Count 1 -ErrorAction Stop *>$null

        # If we get here, it means the ping was successful
        Write-Host "Connecting to TS - OK" -ForegroundColor Green
    }
    catch [System.Net.NetworkInformation.PingException] {
        # If we get here, it means there was an error with the ping
        Write-Host "Connecting to TS - Ping Failed" -ForegroundColor Red
        Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }
    catch {
        # This catch block is for other types of exceptions that may occur during the ping process
        Write-Host "Connecting to TS - Failed" -ForegroundColor Yellow
        Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }

    ""
    "--- Step 7: Change IP based on BPS number ---"
    ""

    $computerHostname = hostname
    Invoke-RestMethod -Uri ("https://pu.bpskozep.hu/deployment/change-ip/$computerHostname/$bpsNumber") -Method Post -Headers @{"Authorization" = "Bearer $PUToken" }
    $tailscaleIP = (Get-NetIPAddress -InterfaceAlias "Tailscale" | Where-Object { $_.AddressFamily -eq 'IPv4' }).IPAddress
    if ($tailscaleIP -eq "100.100.25.$bpsNumber") {
        Write-Host "Changing IP: 100.100.25.$bpsNumber - OK" -ForegroundColor Green
    }
    else {
        Write-Host "Changing IP - Failed" -ForegroundColor Red
        Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }

    ""
    "--- Step 8: Join Active Directory and restart ---"
    ""

    $deployPass = Invoke-RestMethod "https://pu.bpskozep.hu/deployment/get-deploy-pass" -Headers @{"Authorization" = "Bearer $PUToken" }

    $domain = "server.bpskozep.hu"
    $username = "bpskozep\deploy.karoly"
    $password = $deployPass | ConvertTo-SecureString -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($username, $password)

    Add-Computer -DomainName $domain -NewName $newComputerName -Credential $credential -Force

    #Check if domain join was successful
    if ((Get-WmiObject win32_computersystem).partofdomain -eq $true) {
        Write-Host "Joining domain - OK" -ForegroundColor Green
    }
    else {
        Write-Host "Joining domain - Failed" -ForegroundColor Red
        Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }

    Write-Host "Setup done :) - Restarting in 5 seconds..." -ForegroundColor Green
    Invoke-RestMethod ("https://pu.bpskozep.hu/deployment/discord-webhook/$newComputerName") -Headers @{"Authorization" = "Bearer $PUToken" }
    Start-Sleep 5
    Restart-Computer -Force
}
catch {
    Write-Host $_.Exception.Message
    Write-Host 'Run failed, press any key to exit' -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

