Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$logDir = Join-Path $env:TEMP "Chrome_Logs"  
$desktopPath = [Environment]::GetFolderPath("Desktop")
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logsSubDir = Join-Path $logDir "logs_$timestamp"
$flagFile = Join-Path $logDir "logging_active.flag"
$chromeProcessIdFile = Join-Path $logDir "chrome_process_id.txt"

$form = New-Object System.Windows.Forms.Form
$form.Text = "Chrome Log Collector"
$form.Size = New-Object System.Drawing.Size(480, 420)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::White

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$titleLabel.Size = New-Object System.Drawing.Size(420, 30)
$titleLabel.Text = "Chrome Log Collector"
$titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($titleLabel)

$descLabel = New-Object System.Windows.Forms.Label
$descLabel.Location = New-Object System.Drawing.Point(20, 60)
$descLabel.Size = New-Object System.Drawing.Size(420, 40)
$descLabel.Text = "This tool collects detailed Chrome logs to help troubleshoot web application issues."
$descLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.Controls.Add($descLabel)

$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Location = New-Object System.Drawing.Point(20, 110)
$statusPanel.Size = New-Object System.Drawing.Size(420, 35)
$statusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$statusPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)

$statusText = New-Object System.Windows.Forms.Label
$statusText.Location = New-Object System.Drawing.Point(10, 5)
$statusText.Size = New-Object System.Drawing.Size(400, 25)
$statusText.Text = "Ready to start logging"
$statusText.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$statusText.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusPanel.Controls.Add($statusText)

$form.Controls.Add($statusPanel)

$statusIndicator = New-Object System.Windows.Forms.Panel
$statusIndicator.Location = New-Object System.Drawing.Point(390, 117)
$statusIndicator.Size = New-Object System.Drawing.Size(20, 20)
$statusIndicator.BackColor = [System.Drawing.Color]::Gray
$statusIndicator.Paint = {
    $brush = New-Object System.Drawing.SolidBrush($this.BackColor)
    $graphics = $_.Graphics
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.FillEllipse($brush, 0, 0, $this.Width, $this.Height)
    $brush.Dispose()
}
$form.Controls.Add($statusIndicator)

$instructionsPanel = New-Object System.Windows.Forms.Panel
$instructionsPanel.Location = New-Object System.Drawing.Point(20, 155)
$instructionsPanel.Size = New-Object System.Drawing.Size(420, 160)
$instructionsPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$instructionsPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)

$instructionsTitle = New-Object System.Windows.Forms.Label
$instructionsTitle.Location = New-Object System.Drawing.Point(10, 10)
$instructionsTitle.Size = New-Object System.Drawing.Size(400, 20)
$instructionsTitle.Text = "Instructions:"
$instructionsTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$instructionsPanel.Controls.Add($instructionsTitle)

$instructionsText = New-Object System.Windows.Forms.Label
$instructionsText.Location = New-Object System.Drawing.Point(10, 35)
$instructionsText.Size = New-Object System.Drawing.Size(400, 115)
$instructionsText.Text = "1. Click 'START LOGGING' to launch Chrome with logging enabled`n`n2. Reproduce the issue you're experiencing in Chrome`n`n3. Return to this tool and click 'STOP AND COLLECT LOGS'`n`n4. Share the log file from your desktop with technical support"
$instructionsText.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$instructionsPanel.Controls.Add($instructionsText)

$form.Controls.Add($instructionsPanel)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Location = New-Object System.Drawing.Point(20, 330)
$startButton.Size = New-Object System.Drawing.Size(200, 40)
$startButton.Text = "START LOGGING"
$startButton.BackColor = [System.Drawing.Color]::FromArgb(46, 204, 113)
$startButton.ForeColor = [System.Drawing.Color]::White
$startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$startButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($startButton)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Location = New-Object System.Drawing.Point(240, 330)
$stopButton.Size = New-Object System.Drawing.Size(200, 40)
$stopButton.Text = "STOP AND COLLECT LOGS"
$stopButton.BackColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
$stopButton.ForeColor = [System.Drawing.Color]::White
$stopButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$stopButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$stopButton.Enabled = $false
$form.Controls.Add($stopButton)

function Update-LoggingState {
    param (
        [bool]$isLogging
    )
    
    if ($isLogging) {
        $statusText.Text = "LOGGING ACTIVE - Chrome running with logging enabled"
        $statusText.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
        $statusText.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $statusIndicator.BackColor = [System.Drawing.Color]::FromArgb(46, 204, 113)
        $startButton.Text = "LOGGING IN PROGRESS..."
        $startButton.BackColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
        $startButton.Enabled = $false
        $stopButton.Enabled = $true
    } else {
        $statusText.Text = "Ready to start logging"
        $statusText.ForeColor = [System.Drawing.Color]::Black
        $statusText.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $statusIndicator.BackColor = [System.Drawing.Color]::Gray
        $startButton.Text = "START LOGGING"
        $startButton.BackColor = [System.Drawing.Color]::FromArgb(46, 204, 113)
        $startButton.Enabled = $true
        $stopButton.Text = "STOP AND COLLECT LOGS"
        $stopButton.Enabled = $false
    }
    
    $statusIndicator.Invalidate()
    $form.Refresh()
}

if (Test-Path $flagFile) {
    Update-LoggingState -isLogging $true
}

$startButton.Add_Click({
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    if (-not (Test-Path $logsSubDir)) {
        New-Item -ItemType Directory -Path $logsSubDir | Out-Null
    }
    "Logging started at $(Get-Date)" | Out-File $flagFile
    
    $chromePaths = @(
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "${env:LOCALAPPDATA}\Google\Chrome\Application\chrome.exe"
    )
    
    $chromePath = $null
    
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            $chromePath = $path
            Write-Host "Found Chrome at standard path: $chromePath"
            break
        }
    }

    if (-not $chromePath) {
        try {
            $regPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
            )
            
            foreach ($regPath in $regPaths) {
                $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($reg -and ($reg.'(Default)') -and (Test-Path $reg.'(Default)')) {
                    $chromePath = $reg.'(Default)'
                    Write-Host "Found Chrome via registry: $chromePath"
                    break
                }
            }
        } catch {
            Write-Host "Registry lookup failed: $_"
        }
    }
    
    if (-not $chromePath) {
        try {
            $chromePath = (Get-Command "chrome.exe" -ErrorAction SilentlyContinue).Source
            if ($chromePath) {
                Write-Host "Found Chrome in PATH: $chromePath"
            }
        } catch {
            Write-Host "PATH lookup failed: $_"
        }
    }
    
    
    if (-not $chromePath) {
        [System.Windows.Forms.MessageBox]::Show("Chrome not found. Please install Chrome and try again.", "Browser Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    
    try {
        New-Item -ItemType Directory -Path (Split-Path -Parent "$logsSubDir\chrome_debug.log") -Force | Out-Null
        
        try {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $logsSubDir -AclObject $acl -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Unable to set permissions, but continuing: $_"
        }
        
        $chromeArgs = @(
            "--enable-logging", 
            "--v=1", 
            "--log-net-log=`"$logsSubDir\netlog.json`"",
            "--enable-logging=stderr",
            "--enable-crash-reporter",
            "--log-file=`"$logsSubDir\chrome_debug.log`""
        )
        
        try {
            Start-Process -FilePath $chromePath -ArgumentList $chromeArgs -WindowStyle Hidden
            "1" | Out-File -FilePath $flagFile -Force
            
            $statusText.Text = "LOGGING ACTIVE - Chrome running with logging enabled"
            $statusText.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
            Update-LoggingState -isLogging $true
        } catch {
            Write-Host "Error starting Chrome: $_"
            $statusText.Text = "Failed to start Chrome with logging enabled. Please try again."
            $statusText.ForeColor = [System.Drawing.Color]::Red
            Update-LoggingState -isLogging $false
            return
        }
        
        Start-Sleep -Seconds 2
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error starting Chrome: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    
    $chromeProcess.Id | Out-File $chromeProcessIdFile
    Update-LoggingState -isLogging $true
})

$stopButton.Add_Click({
    $stopButton.Enabled = $false
    $stopButton.Text = "COLLECTING LOGS..."
    $statusText.Text = "Collecting logs, please wait..."
    $statusText.ForeColor = [System.Drawing.Color]::FromArgb(230, 126, 34)
    $form.Refresh()
    
    try {
        Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
        Write-Host "Closed all Chrome instances"
    } catch {
        Write-Host "Error closing Chrome: $_"
    }
    
    if (Test-Path $flagFile) {
        Remove-Item $flagFile -Force
    }
    
    $logFiles = Get-ChildItem -Path $logsSubDir -Recurse -File -ErrorAction SilentlyContinue
    
    if (-not $logFiles -or $logFiles.Count -eq 0) {
        $diagnosticLogPath = Join-Path $logsSubDir "diagnostic_info.txt"
        
        $diagnosticInfo = @"
Chrome Log Collector Diagnostic Information
Generated: $(Get-Date)

System Information:
------------------
OS: $([System.Environment]::OSVersion.VersionString)
PowerShell Version: $($PSVersionTable.PSVersion)
Computer Name: $env:COMPUTERNAME
Username: $env:USERNAME

Chrome Information:
------------------
"@
        
        $chromePaths = @(
            "${env:ProgramFiles}\Google\Chrome\Application",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application",
            "${env:LOCALAPPDATA}\Google\Chrome\Application"
        )
        
        $chromeVersionFound = $false
        foreach ($path in $chromePaths) {
            if (Test-Path $path) {
                $versionFolders = Get-ChildItem -Path $path -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' }
                if ($versionFolders) {
                    $diagnosticInfo += "Chrome Version: $($versionFolders[0].Name)`n"
                    $diagnosticInfo += "Chrome Path: $path`n"
                    $chromeVersionFound = $true
                    break
                }
            }
        }
        
        if (-not $chromeVersionFound) {
            $diagnosticInfo += "Chrome Version: Not found`n"
        }
        
        $diagnosticInfo += @"

--------------------------
Log Directory: $logsSubDir
Chrome Process ID File: $chromeProcessIdFile
Flag File: $flagFile

Error: No log files were generated during the Chrome session.
Possible causes:
- Chrome didn't start properly with logging enabled
- Chrome crashed immediately after starting
- Insufficient permissions to write log files
- Antivirus or security software blocked log creation

"@
        
        $diagnosticInfo | Out-File -FilePath $diagnosticLogPath -Encoding utf8
        
        $logFiles = Get-ChildItem -Path $logsSubDir -Recurse -File -ErrorAction SilentlyContinue
    }
    
    # Create zip file
    $zipFileName = "ChromeLogs_$timestamp.zip"
    $zipFilePath = Join-Path $desktopPath $zipFileName
    
    try {
        Compress-Archive -Path $logsSubDir -DestinationPath $zipFilePath -Force -ErrorAction Stop
    }
    catch {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($logsSubDir, $zipFilePath)
        }
        catch {
            try {
                $shell = New-Object -ComObject Shell.Application
                $zipFile = $shell.NameSpace($zipFilePath)
                $tempFolder = Join-Path $env:TEMP "ChromeLogsTemp_$timestamp"
                New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
                
                foreach ($file in $logFiles) {
                    Copy-Item -Path $file.FullName -Destination $tempFolder -Force
                }
                
                $zipFile.CopyHere($tempFolder)
                
                Start-Sleep -Seconds 10
                
                Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
            }
            catch {
                $desktopFolder = Join-Path $desktopPath "ChromeLogs_$timestamp"
                New-Item -ItemType Directory -Path $desktopFolder -Force | Out-Null
                
                foreach ($file in $logFiles) {
                    Copy-Item -Path $file.FullName -Destination $desktopFolder -Force
                }
                
                $zipFileName = "(Folder) ChromeLogs_$timestamp"
                $zipFilePath = $desktopFolder
            }
        }
    }
    
    try {
        if (Test-Path $logsSubDir) {
            Remove-Item -Path $logsSubDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "Failed to clean up temporary files: $_"
    }
    
    $statusText.Text = "Logs collected and saved to desktop: $zipFileName"
    $statusText.ForeColor = [System.Drawing.Color]::FromArgb(41, 128, 185)
    $statusIndicator.BackColor = [System.Drawing.Color]::FromArgb(41, 128, 185)
    $statusIndicator.Invalidate()
    $form.Refresh()
    
    Start-Sleep -Seconds 3
    Update-LoggingState -isLogging $false
})

$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
