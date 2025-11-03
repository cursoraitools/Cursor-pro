# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Color definitions
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

# Configuration file paths
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# PowerShell native method to generate random strings
function Generate-RandomString {
    param([int]$Length)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $result
}

# Modify Cursor core JS files to bypass device identification (ported from macOS version)
function Modify-CursorJSFiles {
    Write-Host ""
    Write-Host "$BLUE🔧 [Core Modification]$NC Starting to modify Cursor core JS files to bypass device identification..."
    Write-Host ""

    # Windows Cursor application path
    $cursorAppPath = "${env:LOCALAPPDATA}\Programs\Cursor"
    if (-not (Test-Path $cursorAppPath)) {
        # Try other possible installation paths
        $alternatePaths = @(
            "${env:ProgramFiles}\Cursor",
            "${env:ProgramFiles(x86)}\Cursor",
            "${env:USERPROFILE}\AppData\Local\Programs\Cursor"
        )

        foreach ($path in $alternatePaths) {
            if (Test-Path $path) {
                $cursorAppPath = $path
                break
            }
        }

        if (-not (Test-Path $cursorAppPath)) {
            Write-Host "$RED❌ [Error]$NC Cursor installation path not found"
            Write-Host "$YELLOW💡 [Tip]$NC Please ensure Cursor is installed correctly"
            return $false
        }
    }

    Write-Host "$GREEN✅ [Found]$NC Found Cursor installation path: $cursorAppPath"

    # Generate new device identifiers
    $newUuid = [System.Guid]::NewGuid().ToString().ToLower()
    $machineId = "auth0|user_$(Generate-RandomString -Length 32)"
    $deviceId = [System.Guid]::NewGuid().ToString().ToLower()
    $macMachineId = Generate-RandomString -Length 64

    Write-Host "$GREEN🔑 [Generated]$NC Generated new device identifiers"

    # Target JS files (Windows paths)
    $jsFiles = @(
        "$cursorAppPath\resources\app\out\vs\workbench\api\node\extensionHostProcess.js",
        "$cursorAppPath\resources\app\out\main.js",
        "$cursorAppPath\resources\app\out\vs\code\node\cliProcessMain.js"
    )

    $modifiedCount = 0
    $needModification = $false

    # Check whether modification is needed
    Write-Host "$BLUE🔍 [Check]$NC Checking JS file modification status..."
    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️  [Warning]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -notmatch "return crypto\.randomUUID\(\)") {
            Write-Host "$BLUE📝 [Needed]$NC File requires modification: $(Split-Path $file -Leaf)"
            $needModification = $true
            break
        } else {
            Write-Host "$GREEN✅ [Modified]$NC File already modified: $(Split-Path $file -Leaf)"
        }
    }

    if (-not $needModification) {
        Write-Host "$GREEN✅ [Skip]$NC All JS files are already modified; no action needed"
        return $true
    }

    # Close Cursor processes
    Write-Host "$BLUE🔄 [Close]$NC Closing Cursor processes to modify files..."
    Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3 | Out-Null

    # Create backup
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$env:TEMP\Cursor_JS_Backup_$timestamp"

    Write-Host "$BLUE💾 [Backup]$NC Creating backup of Cursor JS files..."
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        foreach ($file in $jsFiles) {
            if (Test-Path $file) {
                $fileName = Split-Path $file -Leaf
                Copy-Item $file "$backupPath\$fileName" -Force
            }
        }
        Write-Host "$GREEN✅ [Backup]$NC Backup created successfully: $backupPath"
    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to create backup: $($_.Exception.Message)"
        return $false
    }

    # Modify JS files
    Write-Host "$BLUE🔧 [Modify]$NC Starting to modify JS files..."

    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️  [Skip]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        Write-Host "$BLUE📝 [Process]$NC Processing: $(Split-Path $file -Leaf)"

        try {
            $content = Get-Content $file -Raw -Encoding UTF8

            # Check whether already modified
            if ($content -match "return crypto\.randomUUID\(\)" -or $content -match "// Cursor ID 修改工具注入") {
                Write-Host "$GREEN✅ [Skip]$NC File already modified"
                $modifiedCount++
                continue
            }

            # JavaScript injection code compatible with ES modules
            $timestampVar = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            $injectCode = @"
// Cursor ID Modifier Injection - $(Get-Date) - ES module compatible version
import crypto from 'crypto';

// Save original function reference
const originalRandomUUID_${timestampVar} = crypto.randomUUID;

// Override crypto.randomUUID method
crypto.randomUUID = function() {
    return '${newUuid}';
};

// Override all possible system ID functions - ES module compatible version
globalThis.getMachineId = function() { return '${machineId}'; };
globalThis.getDeviceId = function() { return '${deviceId}'; };
globalThis.macMachineId = '${macMachineId}';

// Ensure accessibility across environments
if (typeof window !== 'undefined') {
    window.getMachineId = globalThis.getMachineId;
    window.getDeviceId = globalThis.getDeviceId;
    window.macMachineId = globalThis.macMachineId;
}

// Ensure top-level execution
console.log('Cursor device identifiers successfully overridden - ES module version');

"@

            # Method 1: Find IOPlatformUUID-related functions
            if ($content -match "IOPlatformUUID") {
                Write-Host "$BLUE🔍 [Found]$NC Found IOPlatformUUID keyword"

                # Modify for different function patterns
                if ($content -match "function a\$") {
                    $content = $content -replace "function a\$\(t\)\{switch", "function a`$(t){return crypto.randomUUID(); switch"
                    Write-Host "$GREEN✅ [Success]$NC Modified a`$ function successfully"
                    $modifiedCount++
                    continue
                }

                # General injection method
                $content = $injectCode + $content
                Write-Host "$GREEN✅ [Success]$NC General injection method applied successfully"
                $modifiedCount++
            }
            # Method 2: Find other device ID related functions
            elseif ($content -match "function t\$\(\)" -or $content -match "async function y5") {
                Write-Host "$BLUE🔍 [Found]$NC Found device ID related functions"

                # Modify MAC address retrieval function
                if ($content -match "function t\$\(\)") {
                    $content = $content -replace "function t\$\(\)\{", "function t`$(){return `"00:00:00:00:00:00`";"
                    Write-Host "$GREEN✅ [Success]$NC Modified MAC address retrieval function"
                }

                # Modify device ID retrieval function
                if ($content -match "async function y5") {
                    $content = $content -replace "async function y5\(t\)\{", "async function y5(t){return crypto.randomUUID();"
                    Write-Host "$GREEN✅ [Success]$NC Modified device ID retrieval function"
                }

                $modifiedCount++
            }
            else {
                Write-Host "$YELLOW⚠️  [Warning]$NC No known device ID function pattern found; using general injection"
                $content = $injectCode + $content
                $modifiedCount++
            }

            # Write modified content
            Set-Content -Path $file -Value $content -Encoding UTF8 -NoNewline
            Write-Host "$GREEN✅ [Done]$NC File modification completed: $(Split-Path $file -Leaf)"

        } catch {
            Write-Host "$RED❌ [Error]$NC Failed to modify file: $($_.Exception.Message)"
            # Attempt to restore from backup
            $fileName = Split-Path $file -Leaf
            $backupFile = "$backupPath\$fileName"
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $file -Force
                Write-Host "$YELLOW🔄 [Restore]$NC Restored file from backup"
            }
        }
    }

    if ($modifiedCount -gt 0) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Done]$NC Successfully modified $modifiedCount JS files"
        Write-Host "$BLUE💾 [Backup]$NC Original files backup location: $backupPath"
        Write-Host "$BLUE💡 [Info]$NC JavaScript injection enabled to bypass device identification"
        return $true
    } else {
        Write-Host "$RED❌ [Failure]$NC Did not successfully modify any files"
        return $false
    }
}


# 🚀 New: Remove Cursor trial folders feature
function Remove-CursorTrialFolders {
    Write-Host ""
    Write-Host "$GREEN🎯 [Core]$NC Executing Cursor trial-protection folder removal..."
    Write-Host "$BLUE📋 [Info]$NC This will delete specified Cursor folders to reset trial state"
    Write-Host ""

    # Define folder paths to delete
    $foldersToDelete = @()

    # Windows Administrator user paths
    $adminPaths = @(
        "C:\Users\Administrator\.cursor",
        "C:\Users\Administrator\AppData\Roaming\Cursor"
    )

    # Current user paths
    $currentUserPaths = @(
        "$env:USERPROFILE\.cursor",
        "$env:APPDATA\Cursor"
    )

    # Combine all paths
    $foldersToDelete += $adminPaths
    $foldersToDelete += $currentUserPaths

    Write-Host "$BLUE📂 [Scan]$NC Will check the following folders:"
    foreach ($folder in $foldersToDelete) {
        Write-Host "   📁 $folder"
    }
    Write-Host ""

    $deletedCount = 0
    $skippedCount = 0
    $errorCount = 0

    # Delete specified folders
    foreach ($folder in $foldersToDelete) {
        Write-Host "$BLUE🔍 [Check]$NC Checking folder: $folder"

        if (Test-Path $folder) {
            try {
                Write-Host "$YELLOW⚠️  [Warning]$NC Folder exists; deleting..."
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folder"
                $deletedCount++
            }
            catch {
                Write-Host "$RED❌ [Error]$NC Failed to delete folder: $folder"
                Write-Host "$RED💥 [Detail]$NC Error: $($_.Exception.Message)"
                $errorCount++
            }
        } else {
            Write-Host "$YELLOW⏭️  [Skip]$NC Folder does not exist: $folder"
            $skippedCount++
        }
        Write-Host ""
    }

    # Show operation statistics
    Write-Host "$GREEN📊 [Stats]$NC Operation summary:"
    Write-Host "   ✅ Deleted successfully: $deletedCount folders"
    Write-Host "   ⏭️  Skipped: $skippedCount folders"
    Write-Host "   ❌ Deletion failed: $errorCount folders"
    Write-Host ""

    if ($deletedCount -gt 0) {
        Write-Host "$GREEN🎉 [Done]$NC Cursor trial-protection folder deletion completed!"

        # 🔧 Pre-create required directory structure to avoid permission issues
        Write-Host "$BLUE🔧 [Fix]$NC Pre-creating required directory structure to avoid permission issues..."

        $cursorAppData = "$env:APPDATA\Cursor"
        $cursorLocalAppData = "$env:LOCALAPPDATA\cursor"
        $cursorUserProfile = "$env:USERPROFILE\.cursor"

        # Create main directories
        try {
            if (-not (Test-Path $cursorAppData)) {
                New-Item -ItemType Directory -Path $cursorAppData -Force | Out-Null
            }
            if (-not (Test-Path $cursorUserProfile)) {
                New-Item -ItemType Directory -Path $cursorUserProfile -Force | Out-Null
            }
            Write-Host "$GREEN✅ [Done]$NC Directory structure pre-creation completed"
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Issue while pre-creating directories: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW🤔 [Tip]$NC No folders found to delete; may already be clean"
    }
    Write-Host ""
}

# 🔄 Restart Cursor and wait for config to be generated
function Restart-CursorAndWait {
    Write-Host ""
    Write-Host "$GREEN🔄 [Restart]$NC Restarting Cursor to regenerate config..."

    if (-not $global:CursorProcessInfo) {
        Write-Host "$RED❌ [Error]$NC Cursor process info not found; cannot restart"
        return $false
    }

    $cursorPath = $global:CursorProcessInfo.Path

    # Fix: Ensure path is a string type
    if ($cursorPath -is [array]) {
        $cursorPath = $cursorPath[0]
    }

    # Validate path is not empty
    if ([string]::IsNullOrEmpty($cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor path is empty"
        return $false
    }

    Write-Host "$BLUE📍 [Path]$NC Using path: $cursorPath"

    if (-not (Test-Path $cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor executable does not exist: $cursorPath"

        # Try using fallback paths
        $backupPaths = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:PROGRAMFILES\Cursor\Cursor.exe",
            "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
        )

        $foundPath = $null
        foreach ($backupPath in $backupPaths) {
            if (Test-Path $backupPath) {
                $foundPath = $backupPath
                Write-Host "$GREEN💡 [Found]$NC Using fallback path: $foundPath"
                break
            }
        }

        if (-not $foundPath) {
            Write-Host "$RED❌ [Error]$NC Could not find a valid Cursor executable"
            return $false
        }

        $cursorPath = $foundPath
    }

    try {
        Write-Host "$GREEN🚀 [Start]$NC Starting Cursor..."
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Hidden

        Write-Host "$YELLOW⏳ [Wait]$NC Waiting 20 seconds for Cursor to start and generate config..."
        Start-Sleep -Seconds 20

        # Check whether config file has been generated
        $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
        $maxWait = 45
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Write-Host "$YELLOW⏳ [Wait]$NC Waiting for config file to be generated... ($waited/$maxWait s)"
            Start-Sleep -Seconds 1
            $waited++
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Config file generated: $configPath"

            # Extra wait to ensure file is fully written
            Write-Host "$YELLOW⏳ [Wait]$NC Waiting 5 seconds to ensure the config file is fully written..."
            Start-Sleep -Seconds 5
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC Config file was not generated within the expected time"
            Write-Host "$BLUE💡 [Tip]$NC You may need to start Cursor manually once to generate the config file"
        }

        # Force close Cursor
        Write-Host "$YELLOW🔄 [Close]$NC Closing Cursor to perform configuration modifications..."
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(5000)
        }

        # Ensure all Cursor processes are closed
        Get-Process -Name "Cursor" -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Process -Name "cursor" -ErrorAction SilentlyContinue | Stop-Process -Force

        Write-Host "$GREEN✅ [Done]$NC Cursor restart process completed"
        return $true

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to restart Cursor: $($_.Exception.Message)"
        Write-Host "$BLUE💡 [Debug]$NC Error details: $($_.Exception.GetType().FullName)"
        return $false
    }
}

# 🔒 Force close all Cursor processes (enhanced)
function Stop-AllCursorProcesses {
    param(
        [int]$MaxRetries = 3,
        [int]$WaitSeconds = 5
    )

    Write-Host "$BLUE🔒 [Process Check]$NC Checking and closing all Cursor-related processes..."

    # Define all possible Cursor process names
    $cursorProcessNames = @(
        "Cursor",
        "cursor",
        "Cursor Helper",
        "Cursor Helper (GPU)",
        "Cursor Helper (Plugin)",
        "Cursor Helper (Renderer)",
        "CursorUpdater"
    )

    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        Write-Host "$BLUE🔍 [Check]$NC Process check $retry/$MaxRetries..."

        $foundProcesses = @()
        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                $foundProcesses += $processes
                Write-Host "$YELLOW⚠️  [Found]$NC Process: $processName (PID: $($processes.Id -join ', '))"
            }
        }

        if ($foundProcesses.Count -eq 0) {
            Write-Host "$GREEN✅ [Success]$NC All Cursor processes have been closed"
            return $true
        }

        Write-Host "$YELLOW🔄 [Close]$NC Closing $($foundProcesses.Count) Cursor processes..."

        # Try graceful close first
        foreach ($process in $foundProcesses) {
            try {
                $process.CloseMainWindow() | Out-Null
                Write-Host "$BLUE  • Graceful close: $($process.ProcessName) (PID: $($process.Id))$NC"
            } catch {
                Write-Host "$YELLOW  • Graceful close failed: $($process.ProcessName)$NC"
            }
        }

        Start-Sleep -Seconds 3

        # Force kill remaining running processes
        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    try {
                        Stop-Process -Id $process.Id -Force
                        Write-Host "$RED  • Force kill: $($process.ProcessName) (PID: $($process.Id))$NC"
                    } catch {
                        Write-Host "$RED  • Force kill failed: $($process.ProcessName)$NC"
                    }
                }
            }
        }

        if ($retry -lt $MaxRetries) {
            Write-Host "$YELLOW⏳ [Wait]$NC Waiting $WaitSeconds seconds before re-checking..."
            Start-Sleep -Seconds $WaitSeconds
        }
    }

    Write-Host "$RED❌ [Failure]$NC After $MaxRetries attempts, Cursor processes are still running"
    return $false
}

# 🔐 Check file permissions and lock state
function Test-FileAccessibility {
    param(
        [string]$FilePath
    )

    Write-Host "$BLUE🔐 [Permission Check]$NC Checking file access: $(Split-Path $FilePath -Leaf)"

    if (-not (Test-Path $FilePath)) {
        Write-Host "$RED❌ [Error]$NC File does not exist"
        return $false
    }

    # Check whether the file is locked
    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        Write-Host "$GREEN✅ [Permission]$NC File is readable/writable, no lock"
        return $true
    } catch [System.IO.IOException] {
        Write-Host "$RED❌ [Locked]$NC File is locked by another process: $($_.Exception.Message)"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Host "$YELLOW⚠️  [Permission]$NC File permissions restricted; attempting to modify..."

        # Attempt to modify file permissions
        try {
            $file = Get-Item $FilePath
            if ($file.IsReadOnly) {
                $file.IsReadOnly = $false
                Write-Host "$GREEN✅ [Fix]$NC Removed read-only attribute"
            }

            # Test again
            $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
            Write-Host "$GREEN✅ [Permission]$NC Permission fix successful"
            return $true
        } catch {
            Write-Host "$RED❌ [Permission]$NC Unable to fix permissions: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Host "$RED❌ [Error]$NC Unknown error: $($_.Exception.Message)"
        return $false
    }
}

# 🧹 Cursor initialization cleanup (ported from older version)
function Invoke-CursorInitialization {
    Write-Host ""
    Write-Host "$GREEN🧹 [Initialize]$NC Running Cursor initialization cleanup..."
    $BASE_PATH = "$env:APPDATA\Cursor\User"

    $filesToDelete = @(
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb"),
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb.backup")
    )

    $folderToCleanContents = Join-Path -Path $BASE_PATH -ChildPath "History"
    $folderToDeleteCompletely = Join-Path -Path $BASE_PATH -ChildPath "workspaceStorage"

    Write-Host "$BLUE🔍 [Debug]$NC Base path: $BASE_PATH"

    # Delete specified files
    foreach ($file in $filesToDelete) {
        Write-Host "$BLUE🔍 [Check]$NC Checking file: $file"
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted file: $file"
            }
            catch {
            Write-Host "$RED❌ [Error]$NC Failed to delete file ${file}: $($_.Exception.Message)"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Skip]$NC File does not exist, skipping delete: $file"
        }
    }

    # Empty contents of specified folder
    Write-Host "$BLUE🔍 [Check]$NC Checking folder to clean: $folderToCleanContents"
    if (Test-Path $folderToCleanContents) {
        try {
            Get-ChildItem -Path $folderToCleanContents -Recurse | Remove-Item -Force -Recurse -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Emptied folder contents: $folderToCleanContents"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to empty folder ${folderToCleanContents}: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skip]$NC Folder does not exist; skipping empty: $folderToCleanContents"
    }

    # Completely delete specified folder
    Write-Host "$BLUE🔍 [Check]$NC Checking folder to delete: $folderToDeleteCompletely"
    if (Test-Path $folderToDeleteCompletely) {
        try {
            Remove-Item -Path $folderToDeleteCompletely -Recurse -Force -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folderToDeleteCompletely"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to delete folder ${folderToDeleteCompletely}: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skip]$NC Folder does not exist; skipping deletion: $folderToDeleteCompletely"
    }

    Write-Host "$GREEN✅ [Done]$NC Cursor initialization cleanup completed"
    Write-Host ""
}

# 🔧 Modify system registry MachineGuid (ported from older version)
function Update-MachineGuid {
    try {
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry MachineGuid..."

        # Check if registry path exists; create if it does not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "$GREEN✅ [Info]$NC Registry path created successfully"
        }

        # Get current MachineGuid; use empty string if missing
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "$GREEN✅ [Info]$NC Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC MachineGuid value does not exist; will create a new value"
            }
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Failed to read registry: $($_.Exception.Message)"
            Write-Host "$YELLOW⚠️  [Warning]$NC Will attempt to create a new MachineGuid value"
        }

        # Create backup file (only if original value exists)
        $backupFile = $null
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            Write-Host "$BLUE💾 [Backup]$NC Backing up registry..."
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($backupResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Backup]$NC Registry entry backed up to: $backupFile"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC Backup creation failed; continuing..."
                $backupFile = $null
            }
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()
        Write-Host "$BLUE🔄 [Generate]$NC New MachineGuid: $newGuid"

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Host "$GREEN✅ [Success]$NC Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "$RED❌ [Error]$NC Registry operation failed: $($_.Exception.Message)"

        # Attempt to restore backup (if exists)
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW🔄 [Restore]$NC Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Restore Success]$NC Restored original registry value"
            } else {
                Write-Host "$RED❌ [Error]$NC Restore failed; please import the backup manually: $backupFile"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC Backup not found or backup creation failed; cannot auto-restore"
        }

        return $false
    }
}

# Check configuration file and environment
function Test-CursorEnvironment {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$BLUE🔍 [Env Check]$NC Checking Cursor environment..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
    $cursorAppData = "$env:APPDATA\Cursor"
    $issues = @()

    # Check config file
    if (-not (Test-Path $configPath)) {
        $issues += "Config file does not exist: $configPath"
    } else {
        try {
            $content = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $content | ConvertFrom-Json -ErrorAction Stop
            Write-Host "$GREEN✅ [Check]$NC Config file format is correct"
        } catch {
            $issues += "Config file format error: $($_.Exception.Message)"
        }
    }

    # Check Cursor directory structure
    if (-not (Test-Path $cursorAppData)) {
        $issues += "Cursor app data directory does not exist: $cursorAppData"
    }

    # Check Cursor installation
    $cursorPaths = @(
        "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
        "$env:PROGRAMFILES\Cursor\Cursor.exe",
        "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
    )

    $cursorFound = $false
    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            Write-Host "$GREEN✅ [Check]$NC Found Cursor installation: $path"
            $cursorFound = $true
            break
        }
    }

    if (-not $cursorFound) {
        $issues += "Cursor installation not found; please ensure Cursor is installed correctly"
    }

    # Return check results
    if ($issues.Count -eq 0) {
        Write-Host "$GREEN✅ [Env Check]$NC All checks passed"
        return @{ Success = $true; Issues = @() }
    } else {
        Write-Host "$RED❌ [Env Check]$NC Found $($issues.Count) issues:"
        foreach ($issue in $issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        return @{ Success = $false; Issues = $issues }
    }
}

# 🛠️ Modify machine code configuration (enhanced)
function Modify-MachineCodeConfig {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$GREEN🛠️  [Config]$NC Modifying machine code configuration..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"

    # Enhanced config file checks
    if (-not (Test-Path $configPath)) {
        Write-Host "$RED❌ [Error]$NC Config file does not exist: $configPath"
        Write-Host ""
        Write-Host "$YELLOW💡 [Solution]$NC Please try the following steps:"
        Write-Host "$BLUE  1️⃣  Manually start the Cursor application$NC"
        Write-Host "$BLUE  2️⃣  Wait for Cursor to fully load (≈30 seconds)$NC"
        Write-Host "$BLUE  3️⃣  Close the Cursor application$NC"
        Write-Host "$BLUE  4️⃣  Run this script again$NC"
        Write-Host ""
        Write-Host "$YELLOW⚠️  [Alternative]$NC If the issue persists:"
        Write-Host "$BLUE  • Choose the script option 'Reset environment + modify machine code'$NC"
        Write-Host "$BLUE  • This option will generate the config file automatically$NC"
        Write-Host ""

    # Provide user choice
    $userChoice = Read-Host "Try starting Cursor now to generate the config file? (y/n)"
        if ($userChoice -match "^(y|yes)$") {
        Write-Host "$BLUE🚀 [Attempt]$NC Trying to start Cursor..."
            return Start-CursorToGenerateConfig
        }

        return $false
    }

    # Ensure processes are fully closed even in MODIFY_ONLY mode
    if ($Mode -eq "MODIFY_ONLY") {
        Write-Host "$BLUE🔒 [Safety Check]$NC Even in modify-only mode, ensure all Cursor processes are fully closed"
        if (-not (Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3)) {
            Write-Host "$RED❌ [Error]$NC Unable to close all Cursor processes; modification may fail"
            $userChoice = Read-Host "Force continue? (y/n)"
            if ($userChoice -notmatch "^(y|yes)$") {
                return $false
            }
        }
    }

    # Check file permissions and lock state
    if (-not (Test-FileAccessibility -FilePath $configPath)) {
        Write-Host "$RED❌ [Error]$NC Unable to access config file; it may be locked or lacking permission"
        return $false
    }

    # Validate config file format and display structure
    try {
        Write-Host "$BLUE🔍 [Validate]$NC Checking config file format..."
        $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
        $config = $originalContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "$GREEN✅ [Validate]$NC Config file format is correct"

        # Display relevant properties in current config
        Write-Host "$BLUE📋 [Current Config]$NC Checking existing telemetry properties:"
        $telemetryProperties = @('telemetry.machineId', 'telemetry.macMachineId', 'telemetry.devDeviceId', 'telemetry.sqmId')
        foreach ($prop in $telemetryProperties) {
            if ($config.PSObject.Properties[$prop]) {
                $value = $config.$prop
                $displayValue = if ($value.Length -gt 20) { "$($value.Substring(0,20))..." } else { $value }
                Write-Host "$GREEN  ✓ ${prop}$NC = $displayValue"
            } else {
                Write-Host "$YELLOW  - ${prop}$NC (does not exist; will create)"
            }
        }
        Write-Host ""
    } catch {
        Write-Host "$RED❌ [Error]$NC Config file format error: $($_.Exception.Message)"
        Write-Host "$YELLOW💡 [Suggestion]$NC Config file may be corrupted; consider choosing 'Reset environment + modify machine code'"
        return $false
    }

    # Implement atomic file operations and retry mechanism
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Host ""
        Write-Host "$BLUE🔄 [Attempt]$NC Attempt $retryCount/$maxRetries to modify..."

        try {
            # Show operation progress
            Write-Host "$BLUE⏳ [Progress]$NC 1/6 - Generating new device identifiers..."

            # Generate new IDs
            $MAC_MACHINE_ID = [System.Guid]::NewGuid().ToString()
            $UUID = [System.Guid]::NewGuid().ToString()
            $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
            $prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
            $randomBytes = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomBytes)
            $randomPart = [System.BitConverter]::ToString($randomBytes) -replace '-',''
            $rng.Dispose()
            $MACHINE_ID = "${prefixHex}${randomPart}"
            $SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

            Write-Host "$GREEN✅ [Progress]$NC 1/6 - Device identifiers generated"

            Write-Host "$BLUE⏳ [Progress]$NC 2/6 - Creating backup directory..."

            # Backup original values (enhanced)
            $backupDir = "$env:APPDATA\Cursor\User\globalStorage\backups"
            if (-not (Test-Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
            }

            $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')_retry$retryCount"
            $backupPath = "$backupDir\$backupName"

            Write-Host "$BLUE⏳ [Progress]$NC 3/6 - Backing up original configuration..."
            Copy-Item $configPath $backupPath -ErrorAction Stop

            # Verify whether backup succeeded
            if (Test-Path $backupPath) {
                $backupSize = (Get-Item $backupPath).Length
                $originalSize = (Get-Item $configPath).Length
                if ($backupSize -eq $originalSize) {
                    Write-Host "$GREEN✅ [Progress]$NC 3/6 - Configuration backup successful: $backupName"
                } else {
                    Write-Host "$YELLOW⚠️  [Warning]$NC Backup file size mismatch; continuing"
                }
            } else {
                throw "Backup file creation failed"
            }

            Write-Host "$BLUE⏳ [Progress]$NC 4/6 - Reading original configuration into memory..."

            # Atomic operation: Read original content into memory
            $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $originalContent | ConvertFrom-Json -ErrorAction Stop

            Write-Host "$BLUE⏳ [Progress]$NC 5/6 - Updating configuration in memory..."

            # Update configuration values (safe approach; ensure properties exist)
            $propertiesToUpdate = @{
                'telemetry.machineId' = $MACHINE_ID
                'telemetry.macMachineId' = $MAC_MACHINE_ID
                'telemetry.devDeviceId' = $UUID
                'telemetry.sqmId' = $SQM_ID
            }

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $value = $property.Value

                # Safely use Add-Member or direct assignment
                if ($config.PSObject.Properties[$key]) {
                    # Property exists; update directly
                    $config.$key = $value
                    Write-Host "$BLUE  ✓ Updated property: ${key}$NC"
                } else {
                    # Property does not exist; add new property
                    $config | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
                    Write-Host "$BLUE  + Added property: ${key}$NC"
                }
            }

            Write-Host "$BLUE⏳ [Progress]$NC 6/6 - Atomically writing new configuration file..."

            # Atomic operation: Delete original file, write new file
            $tempPath = "$configPath.tmp"
            $updatedJson = $config | ConvertTo-Json -Depth 10

            # Write temporary file
            [System.IO.File]::WriteAllText($tempPath, $updatedJson, [System.Text.Encoding]::UTF8)

            # Verify temporary file
            $tempContent = Get-Content $tempPath -Raw -Encoding UTF8
            $tempConfig = $tempContent | ConvertFrom-Json

            # Verify all properties are written correctly
            $tempVerificationPassed = $true
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $tempConfig.$key

                if ($actualValue -ne $expectedValue) {
                    $tempVerificationPassed = $false
                    Write-Host "$RED  ✗ Temporary file verification failed: ${key}$NC"
                    break
                }
            }

            if (-not $tempVerificationPassed) {
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                throw "Temporary file verification failed"
            }

            # Atomic replacement: Delete original file and rename temporary file
            Remove-Item $configPath -Force
            Move-Item $tempPath $configPath

            # Set file to read-only (optional)
            $file = Get-Item $configPath
            $file.IsReadOnly = $false  # Keep writable for subsequent modifications

            # Final verification of modifications
            Write-Host "$BLUE🔍 [Final Verification]$NC Verifying new configuration file..."

            $verifyContent = Get-Content $configPath -Raw -Encoding UTF8
            $verifyConfig = $verifyContent | ConvertFrom-Json

            $verificationPassed = $true
            $verificationResults = @()

            # Safely verify each property
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $verifyConfig.$key

                if ($actualValue -eq $expectedValue) {
                    $verificationResults += "✓ ${key}: Verification passed"
                } else {
                    $verificationResults += "✗ ${key}: Verification failed (Expected: ${expectedValue}, Actual: ${actualValue})"
                    $verificationPassed = $false
                }
            }

            # Show verification results
            Write-Host "$BLUE📋 [Verification Details]$NC"
            foreach ($result in $verificationResults) {
                Write-Host "   $result"
            }

            if ($verificationPassed) {
                Write-Host "$GREEN✅ [Success]$NC Modification succeeded on attempt $retryCount!"
                Write-Host ""
                Write-Host "$GREEN🎉 [Done]$NC Machine code configuration updated!"
                Write-Host "$BLUE📋 [Details]$NC Updated the following identifiers:"
                Write-Host "   🔹 machineId: $MACHINE_ID"
                Write-Host "   🔹 macMachineId: $MAC_MACHINE_ID"
                Write-Host "   🔹 devDeviceId: $UUID"
                Write-Host "   🔹 sqmId: $SQM_ID"
                Write-Host ""
                Write-Host "$GREEN💾 [Backup]$NC Original configuration backed up to: $backupName"

                # 🔒 Add configuration file protection mechanism
                Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
                try {
                    $configFile = Get-Item $configPath
                    $configFile.IsReadOnly = $true
                    Write-Host "$GREEN✅ [Protection]$NC Config file set to read-only to prevent Cursor from overwriting"
                    Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
                } catch {
                    Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                    Write-Host "$BLUE💡 [Suggestion]$NC You can manually set: Right-click file → Properties → check 'Read-only'"
                }
                Write-Host "$BLUE 🔒 [Security]$NC It is recommended to restart Cursor to ensure the configuration takes effect"
                return $true
            } else {
                Write-Host "$RED❌ [Failure]$NC Verification failed on attempt $retryCount"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "$BLUE🔄 [Restore]$NC Restoring backup, preparing to retry..."
                    Copy-Item $backupPath $configPath -Force
                    Start-Sleep -Seconds 2
                    continue  # Continue to next retry
                } else {
                    Write-Host "$RED❌ [Final Failure]$NC All retries failed; restoring original configuration"
                    Copy-Item $backupPath $configPath -Force
                    return $false
                }
            }

        } catch {
            Write-Host "$RED❌ [Exception]$NC Exception on attempt ${retryCount}: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Debug Info]$NC Error type: $($_.Exception.GetType().FullName)"

            # Clean up temporary files
            if (Test-Path "$configPath.tmp") {
                Remove-Item "$configPath.tmp" -Force -ErrorAction SilentlyContinue
            }

            if ($retryCount -lt $maxRetries) {
                Write-Host "$BLUE🔄 [Restore]$NC Restoring backup, preparing to retry..."
                if (Test-Path $backupPath) {
                    Copy-Item $backupPath $configPath -Force
                }
                Start-Sleep -Seconds 3
                continue  # Continue to next retry
            } else {
                Write-Host "$RED❌ [Final Failure]$NC All retries failed"
                # Attempt to restore backup
                if (Test-Path $backupPath) {
                    Write-Host "$BLUE🔄 [Restore]$NC Restoring backup configuration..."
                    try {
                        Copy-Item $backupPath $configPath -Force
                        Write-Host "$GREEN✅ [Restore]$NC Original configuration restored"
                    } catch {
                        Write-Host "$RED❌ [Error]$NC Failed to restore backup: $($_.Exception.Message)"
                    }
                }
                return $false
            }
        }
    }

    # If we reach here, all retries failed
    Write-Host "$RED❌ [Final Failure]$NC Unable to complete modification after $maxRetries attempts"
    return $false

}

#  Start Cursor to generate configuration file
function Start-CursorToGenerateConfig {
    Write-Host "$BLUE🚀 [Start]$NC Trying to start Cursor to generate configuration file..."

    # Find Cursor executable
    $cursorPaths = @(
        "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
        "$env:PROGRAMFILES\Cursor\Cursor.exe",
        "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
    )

    $cursorPath = $null
    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            $cursorPath = $path
            break
        }
    }

    if (-not $cursorPath) {
        Write-Host "$RED❌ [Error]$NC Cursor installation not found; please ensure Cursor is installed correctly"
        return $false
    }

    try {
        Write-Host "$BLUE📍 [Path]$NC Using Cursor path: $cursorPath"

        # Start Cursor
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Normal
        Write-Host "$GREEN🚀 [Start]$NC Cursor started, PID: $($process.Id)"

        Write-Host "$YELLOW⏳ [Wait]$NC Please wait for Cursor to fully load (≈30 seconds)..."
        Write-Host "$BLUE💡 [Tip]$NC You can manually close Cursor after it fully loads"

        # Wait for configuration file generation
        $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
        $maxWait = 60
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Start-Sleep -Seconds 2
            $waited += 2
            if ($waited % 10 -eq 0) {
                Write-Host "$YELLOW⏳ [Wait]$NC Waiting for configuration file generation... ($waited/$maxWait s)"
            }
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Configuration file generated!"
            Write-Host "$BLUE💡 [Tip]$NC You can now close Cursor and rerun the script"
            return $true
        } else {
            Write-Host "$YELLOW⚠️  [Timeout]$NC Configuration file not generated within expected time"
            Write-Host "$BLUE💡 [Suggestion]$NC Try interacting with Cursor (e.g., create a new file) to trigger config generation"
            return $false
        }

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to start Cursor: $($_.Exception.Message)"
        return $false
    }
}

# 🚀 Automatically start Cursor after completion
function Start-CursorAutomatically {
    Write-Host ""
    Write-Host "$GREEN🚀 [Auto Start]$NC Automatically starting Cursor..."
    
    # Get Cursor path from saved info or find it
    $cursorPath = $null
    
    if ($global:CursorProcessInfo -and $global:CursorProcessInfo.Path) {
        $cursorPath = $global:CursorProcessInfo.Path
    } else {
        # Try to find Cursor installation
        $cursorPaths = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:PROGRAMFILES\Cursor\Cursor.exe",
            "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
        )
        
        foreach ($path in $cursorPaths) {
            if (Test-Path $path) {
                $cursorPath = $path
                break
            }
        }
    }
    
    if (-not $cursorPath) {
        Write-Host "$RED❌ [Error]$NC Could not find Cursor installation path"
        Write-Host "$YELLOW💡 [Tip]$NC Please start Cursor manually"
        return $false
    }
    
    try {
        Write-Host "$BLUE📍 [Path]$NC Using Cursor path: $cursorPath"
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Normal
        Write-Host "$GREEN✅ [Success]$NC Cursor started successfully! PID: $($process.Id)"
        Write-Host "$BLUE💡 [Tip]$NC Cursor is now running with the new configuration"
        return $true
    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to start Cursor automatically: $($_.Exception.Message)"
        Write-Host "$YELLOW💡 [Tip]$NC Please start Cursor manually"
        return $false
    }
}

# Function to draw a simple box with content
function Write-Box {
    param(
        [string[]]$Lines,
        [int]$Width = 70
    )
    
    $border = "=" * $Width
    Write-Host $border
    
    foreach ($line in $Lines) {
        Write-Host $line
    }
    
    Write-Host $border
}

# Check administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[Error]$NC Please run this script as Administrator"
    Write-Host "Right-click the script and choose 'Run as administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Logo
Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗    ██████╗  ██████╗   ██████╗
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗   ██╔══██╗ ██╔══██╗  ██╔═══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝   ██████╔╝ ██████╔╝  ██║   ██║
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗   ██╔═══╝  ██╔══██╗  ██║   ██║
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║   ██║      ██║  ██║  ╚██████╔╝
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝      ╚═╝  ╚═╝   ╚═════╝ 

"@
Write-Host "$BLUE================================$NC"
Write-Host "$GREEN🚀   CURSOR PRO          $NC"
Write-Host "$YELLOW📱  Created by: web_master_Team$NC"
Write-Host "$YELLOW🔗  Telegram: https://t.me/cursoraitools $NC"
Write-Host "$YELLOW💻  We create powerful tools and utilities for developers$NC"
Write-Host "$YELLOW💡  [Important] This tool is free. Join our Telegram for updates and support!$NC"
Write-Host "$BLUE================================$NC"

# 🎯 User selection menu
Write-Host ""
Write-Host "$GREEN🎯 [Select Mode]$NC Please choose an action:"
Write-Host ""

# Box 1: Option 1
$option1Lines = @(
    "$BLUE  1️⃣  Modify machine code only$NC",
    "$YELLOW      • Perform machine code modification$NC",
    "$YELLOW      • Inject JS bypass code into core files$NC",
    "$YELLOW      • Skip folder deletion/environment reset steps$NC",
    "$YELLOW      • Keep existing Cursor configuration and data$NC"
)
Write-Box -Lines $option1Lines -Width 70

Write-Host ""

# Box 2: Option 2
$option2Lines = @(
    "$BLUE  2️⃣  Reset environment + modify machine code$NC",
    "$RED      • Perform full environment reset (delete Cursor folders)$NC",
    "$RED      • ⚠️  Configuration will be lost; please back up$NC",
    "$YELLOW      • Modify machine code accordingly$NC",
    "$YELLOW      • Inject JS bypass code into core files$NC",
    "$YELLOW      • This corresponds to the full script behavior$NC"
)
Write-Box -Lines $option2Lines -Width 70

Write-Host ""

# Get user selection
do {
    $userChoice = Read-Host "Enter choice (1 or 2)"
    if ($userChoice -eq "1") {
        Write-Host "$GREEN✅ [Selected]$NC You chose: Modify machine code only"
        $executeMode = "MODIFY_ONLY"
        break
    } elseif ($userChoice -eq "2") {
        Write-Host "$GREEN✅ [Selected]$NC You chose: Reset environment + modify machine code"
        Write-Host "$RED⚠️  [Important Warning]$NC This will delete all Cursor configuration files!"
        $confirmReset = Read-Host "Confirm full reset? (type yes to confirm, any other key to cancel)"
        if ($confirmReset -eq "yes") {
            $executeMode = "RESET_AND_MODIFY"
            break
        } else {
            Write-Host "$YELLOW👋 [Cancelled]$NC User cancelled reset"
            continue
        }
    } else {
        Write-Host "$RED❌ [Error]$NC Invalid choice; please enter 1 or 2"
    }
} while ($true)

Write-Host ""

# 📋 Show execution flow based on selection
if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN📋 [Flow]$NC Modify-only mode will perform these steps:"
    Write-Host "$BLUE  1️⃣  Check Cursor config file$NC"
    Write-Host "$BLUE  2️⃣  Back up existing config file$NC"
    Write-Host "$BLUE  3️⃣  Modify machine code configuration$NC"
    Write-Host "$BLUE  4️⃣  Display completion info$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Will not delete folders or reset environment$NC"
    Write-Host "$YELLOW  • Keep all existing configuration and data$NC"
    Write-Host "$YELLOW  • Original config file will be backed up automatically$NC"
} else {
    Write-Host "$GREEN📋 [Flow]$NC Reset environment + modify machine code will perform these steps:"
    Write-Host "$BLUE  1️⃣  Detect and close Cursor processes$NC"
    Write-Host "$BLUE  2️⃣  Save Cursor program path info$NC"
    Write-Host "$BLUE  3️⃣  Delete specified Cursor trial-related folders$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE  3.5️⃣ Pre-create required directories to avoid permission issues$NC"
    Write-Host "$BLUE  4️⃣  Restart Cursor to generate new configuration file$NC"
    Write-Host "$BLUE  5️⃣  Wait for configuration file to be generated (up to 45s)$NC"
    Write-Host "$BLUE  6️⃣  Close Cursor processes$NC"
    Write-Host "$BLUE  7️⃣  Modify the newly generated machine code configuration file$NC"
    Write-Host "$BLUE  8️⃣  Show operation summary$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Do not operate Cursor manually during execution$NC"
    Write-Host "$YELLOW  • Recommended to close all Cursor windows before execution$NC"
    Write-Host "$YELLOW  • Restart Cursor after completion$NC"
    Write-Host "$YELLOW  • Original config will be backed up to 'backups' folder$NC"
}
Write-Host ""

# 🤔 User confirmation
Write-Host "$GREEN🤔 [Confirm]$NC Please confirm you understand the steps above"
$confirmation = Read-Host "Continue? (type y or yes to proceed, any other key to exit)"
if ($confirmation -notmatch "^(y|yes)$") {
    Write-Host "$YELLOW👋 [Exit]$NC User cancelled; exiting"
    Read-Host "Press Enter to exit"
    exit 0
}
Write-Host "$GREEN✅ [Confirmed]$NC User confirmed to proceed"
Write-Host ""

# Get and display Cursor version
function Get-CursorVersion {
    try {
        # Primary detection path
        $packagePath = "$env:LOCALAPPDATA\\Programs\\cursor\\resources\\app\\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        # Alternate path detection
        $altPath = "$env:LOCALAPPDATA\\cursor\\resources\\app\\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "$YELLOW[Warning]$NC Unable to detect Cursor version"
        Write-Host "$YELLOW[Tip]$NC Please ensure Cursor is installed correctly"
        return $null
    }
    catch {
        Write-Host "$RED[Error]$NC Failed to get Cursor version: $_"
        return $null
    }
}

# Get and display version info
 $cursorVersion = Get-CursorVersion
Write-Host ""

Write-Host "$YELLOW💡 [Important]$NC Latest 1.0.x versions are supported"

Write-Host ""

# 🔍 Check and close Cursor processes
Write-Host "$GREEN🔍 [Check]$NC Checking Cursor processes..."

function Get-ProcessDetails {
    param($processName)
    Write-Host "$BLUE🔍 [Debug]$NC Getting $processName process details:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" |
        Select-Object ProcessId, ExecutablePath, CommandLine |
        Format-List
}

# Define max retries and wait time
$MAX_RETRIES = 5
$WAIT_TIME = 1

# 🔄 Handle process closure and save process info
function Close-CursorProcessAndSaveInfo {
    param($processName)

    $global:CursorProcessInfo = $null

    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "$YELLOW⚠️  [Warning]$NC Found $processName running"

        # 💾 Save process info for subsequent restart - Fix: ensure single process path
        $firstProcess = if ($processes -is [array]) { $processes[0] } else { $processes }
        $processPath = $firstProcess.Path

        # Ensure path is a string rather than an array
        if ($processPath -is [array]) {
            $processPath = $processPath[0]
        }

        $global:CursorProcessInfo = @{
            ProcessName = $firstProcess.ProcessName
            Path = $processPath
            StartTime = $firstProcess.StartTime
        }
        Write-Host "$GREEN💾 [Saved]$NC Saved process info: $($global:CursorProcessInfo.Path)"

        Get-ProcessDetails $processName

        Write-Host "$YELLOW🔄 [Action]$NC Attempting to close $processName..."
        Stop-Process -Name $processName -Force

        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if (-not $process) { break }

            $retryCount++
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Host "$RED❌ [Error]$NC Could not close $processName after $MAX_RETRIES attempts"
                Get-ProcessDetails $processName
                Write-Host "$RED💥 [Error]$NC Please close the process manually and retry"
                Read-Host "Press Enter to exit"
                exit 1
            }
            Write-Host "$YELLOW⏳ [Wait]$NC Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
            Start-Sleep -Seconds $WAIT_TIME
        }
        Write-Host "$GREEN✅ [Success]$NC $processName closed successfully"
    } else {
        Write-Host "$BLUE💡 [Tip]$NC No running $processName process found"
        # 尝试找到Cursor的安装路径
        $cursorPaths = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:PROGRAMFILES\Cursor\Cursor.exe",
            "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
        )

        foreach ($path in $cursorPaths) {
            if (Test-Path $path) {
                $global:CursorProcessInfo = @{
                    ProcessName = "Cursor"
                    Path = $path
                    StartTime = $null
                }
                Write-Host "$GREEN💾 [Found]$NC Found Cursor installation path: $path"
                break
            }
        }

        if (-not $global:CursorProcessInfo) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Cursor installation path not found; using default path"
            $global:CursorProcessInfo = @{
                ProcessName = "Cursor"
                Path = "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe"
                StartTime = $null
            }
        }
    }
}

# Ensure backup directory exists
if (-not (Test-Path $BACKUP_DIR)) {
    try {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        Write-Host "$GREEN✅ [Backup Dir]$NC Backup directory created: $BACKUP_DIR"
    } catch {
        Write-Host "$YELLOW⚠️  [Warning]$NC Failed to create backup directory: $($_.Exception.Message)"
    }
}

# 🚀 Execute functionality based on user selection
if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN🚀 [Start]$NC Starting modify-only mode..."

    # Run environment check first
    $envCheck = Test-CursorEnvironment -Mode "MODIFY_ONLY"
    if (-not $envCheck.Success) {
        Write-Host ""
        Write-Host "$RED❌ [Env Check Failed]$NC Cannot proceed; found the following issues:"
        foreach ($issue in $envCheck.Issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        Write-Host ""
        Write-Host "$YELLOW💡 [Suggestion]$NC Choose one of the following:"
        Write-Host "$BLUE  1️⃣  Choose 'Reset environment + modify machine code' (recommended)$NC"
        Write-Host "$BLUE  2️⃣  Start Cursor once manually, then re-run the script$NC"
        Write-Host "$BLUE  3️⃣  Verify Cursor is installed correctly$NC"
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }

    # 执行机器码修改
    $configSuccess = Modify-MachineCodeConfig -Mode "MODIFY_ONLY"

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Config]$NC Machine code configuration file updated!"

        # Add registry modification
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        # 🔧 New: JavaScript injection (enhanced device bypass)
        Write-Host ""
        Write-Host "$BLUE🔧 [Device Bypass]$NC Performing JavaScript injection..."
        Write-Host "$BLUE💡 [Info]$NC This modifies Cursor core JS files to deepen device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry updated successfully"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JS Injection]$NC JavaScript injection succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Done]$NC All machine code modifications completed (enhanced)!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following:"
                Write-Host "$GREEN  ✓ Cursor config file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JS Injection]$NC JavaScript injection failed; other steps succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Done]$NC Machine code modifications completed!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following:"
                Write-Host "$GREEN  ✓ Cursor config file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partial failure)$NC"
            }

            # 🔒 Add configuration file protection
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Config file set to read-only to prevent Cursor overwriting"
                Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually set: Right-click file → Properties → check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but config update succeeded"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JS Injection]$NC JavaScript injection succeeded"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial]$NC Config updated and JS injection done; registry update failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
                Write-Host "$BLUE📋 [Details]$NC Completed the following:"
                Write-Host "$GREEN  ✓ Cursor config file (storage.json)$NC"
                Write-Host "$YELLOW  ⚠ System registry (MachineGuid) - failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JS Injection]$NC JavaScript injection failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial]$NC Config updated; registry and JS injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
            }

            # 🔒 Protect config file even if registry modification failed
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Config file set to read-only to prevent Cursor overwriting"
                Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually set: Right-click file → Properties → check 'Read-only'"
            }
        }

        Write-Host "$BLUE💡 [Tip]$NC Starting Cursor automatically with the new machine code configuration"
        
        # Automatically start Cursor
        Start-CursorAutomatically
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failure]$NC Machine code modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Try 'Reset environment + modify machine code'"
    }
} else {
    # Full reset environment + modify machine code flow
    Write-Host "$GREEN🚀 [Start]$NC Starting reset environment + modify machine code..."

    # 🚀 关闭所有 Cursor 进程并保存信息
    Close-CursorProcessAndSaveInfo "Cursor"
    if (-not $global:CursorProcessInfo) {
        Close-CursorProcessAndSaveInfo "cursor"
    }

    # 🚨 Important warning
    Write-Host ""
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host "$YELLOW⚠️  [Risk Control]$NC Cursor's risk control is very strict!"
    Write-Host "$YELLOW⚠️  [Must Delete]$NC You must completely delete the specified folders; no remnants"
    Write-Host "$YELLOW⚠️  [Trial Protection]$NC Only thorough cleanup can prevent losing trial Pro status"
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host ""

    # 🎯 Execute Cursor trial-protection folder deletion
    Write-Host "$GREEN🚀 [Start]$NC Starting core operation..."
    Remove-CursorTrialFolders



    # 🔄 Restart Cursor to regenerate configuration
    Restart-CursorAndWait

    # 🛠️ Modify machine code configuration
    $configSuccess = Modify-MachineCodeConfig
    
    # 🧹 Run Cursor initialization cleanup
    Invoke-CursorInitialization

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Config]$NC Machine code configuration file updated!"

        # Add registry modification
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        # 🔧 New: JavaScript injection (enhanced device bypass)
        Write-Host ""
        Write-Host "$BLUE🔧 [Device Bypass]$NC Performing JavaScript injection..."
        Write-Host "$BLUE💡 [Info]$NC This modifies Cursor core JS files to deepen device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry updated successfully"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JS Injection]$NC JavaScript injection succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Done]$NC All operations completed (enhanced)!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following actions:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$GREEN  ✓ Updated system registry$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JS Injection]$NC JavaScript injection failed; other steps succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Done]$NC All operations completed!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following actions:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$GREEN  ✓ Updated system registry$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partial failure)$NC"
            }

            # 🔒 Add configuration file protection mechanism
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Config file set to read-only to prevent Cursor overwriting"
                Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually set: Right-click file → Properties → check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but other steps succeeded"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JS Injection]$NC JavaScript injection succeeded"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial]$NC Most operations completed; registry modification failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
                Write-Host "$BLUE📋 [Details]$NC Completed the following actions:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$YELLOW  ⚠ Updated system registry - failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JS Injection]$NC JavaScript injection failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial]$NC Most operations completed; registry and JS injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
            }

            # 🔒 Protect config file even if registry modification failed
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Config file set to read-only to prevent Cursor overwriting"
                Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually set: Right-click file → Properties → check 'Read-only'"
            }
        }
        
        # Automatically start Cursor after successful completion
        Write-Host ""
        Write-Host "$BLUE💡 [Tip]$NC Starting Cursor automatically with the new configuration"
        Start-CursorAutomatically
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failure]$NC Machine code configuration modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Please check the error messages and try again"
    }
}


# 📱 Show team info
Write-Host ""
Write-Host "$GREEN================================$NC"
Write-Host "$GREEN📱  Created by: web_master_Team$NC"
Write-Host "$GREEN🔗  Telegram: https://t.me/cursoraitools $NC"
Write-Host "$GREEN💻  We create powerful tools and utilities for developers$NC"
Write-Host "$GREEN⭐  Join our Telegram channel for more tools, updates, and support!$NC"
Write-Host "$GREEN================================$NC"
Write-Host ""

# 🎉 Script execution completed
Write-Host "$GREEN🎉 [Script Complete]$NC Thank you for using the Cursor machine code modification tool!"
Write-Host "$BLUE💡 [Tip]$NC Script will stay open. You can close this window when done."
Write-Host ""
Write-Host "$BLUE💡 [Info]$NC Cursor should be running now. You can close this PowerShell window if you want."

