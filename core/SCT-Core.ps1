# core/SCT-Core.ps1
# Shared helper functions for Start-SCT.ps1
# Do not run this file directly - it is dot-sourced by Start-SCT.ps1

Set-StrictMode -Version Latest

# =============================================================================
# BANNER
# =============================================================================

function Show-SCTBanner {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================================+" -ForegroundColor Cyan
    Write-Host "  |                                                                            |" -ForegroundColor Cyan
    Write-Host "  |   SECURITY CONTROLS TESTING FRAMEWORK  (SCT)                              |" -ForegroundColor Cyan
    Write-Host "  |   Endpoint Detection & Prevention Evaluation  |  MITRE ATT&CK Mapped      |" -ForegroundColor Cyan
    Write-Host "  |   Platform: Windows 10 / 11  |  PowerShell 5.1+  |  Isolated VM Only     |" -ForegroundColor Cyan
    Write-Host "  |                                                                            |" -ForegroundColor Cyan
    Write-Host "  +============================================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  !! WARNING: Run inside an isolated lab VM only. Never run on production systems. !!" -ForegroundColor Red
    Write-Host ""
}

# =============================================================================
# MODULE DISCOVERY
# =============================================================================

function Get-SCTModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScenariosPath
    )

    $modules = @()

    if (-not (Test-Path $ScenariosPath)) {
        Write-Warning "Scenarios path not found: $ScenariosPath"
        return $modules
    }

    $dirs = Get-ChildItem -Path $ScenariosPath -Directory | Sort-Object Name

    foreach ($dir in $dirs) {
        $jsonFile = Join-Path $dir.FullName 'module.json'
        if (-not (Test-Path $jsonFile)) { continue }

        try {
            $raw    = Get-Content -Path $jsonFile -Raw -Encoding UTF8
            $module = $raw | ConvertFrom-Json

            # Attach the folder path so callers can resolve script paths
            $module | Add-Member -NotePropertyName 'ScriptDir' `
                -NotePropertyValue $dir.FullName -Force

            $modules += $module
        } catch {
            Write-Warning "Could not load module.json in '$($dir.Name)': $($_.Exception.Message)"
        }
    }

    return $modules
}

# =============================================================================
# MAIN MENU
# =============================================================================

function Show-SCTMainMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Modules,
        [string]$Control
    )

    Write-Host ""
    Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  MAIN MENU                                                                 |" -ForegroundColor Cyan
    if ($Control) {
        $tag = "  |  Control : $Control"
        Write-Host ($tag.PadRight(77) + '|') -ForegroundColor Cyan
    }
    Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What would you like to test today?" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $Modules.Count; $i++) {
        $m            = $Modules[$i]
        $vectorCount  = if ($m.vectors) { "($(@($m.vectors).Count) vectors)" } else { '(0 vectors)' }
        $label        = "[$($i + 1)]"
        Write-Host ("  {0,-5} {1,-45} {2}" -f $label, $m.display_name, $vectorCount) -ForegroundColor White
        Write-Host ("        $($m.description)") -ForegroundColor DarkGray
        Write-Host ""
    }

    Write-Host "  [V]   View Results Summary" -ForegroundColor Yellow
    Write-Host "  [Q]   Quit" -ForegroundColor Yellow
    Write-Host ""
}

# =============================================================================
# MODULE SUB-MENU + DISPATCH
# =============================================================================

function Invoke-SCTModuleMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Module,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$SamplesPath,
        [Parameter(Mandatory)] [string]$ScenarioRoot,
        [Parameter(Mandatory)] [string]$ResultsPath,
        [Parameter(Mandatory)] [string]$TechResultsPath
    )

    while ($true) {
        Write-Host ""
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ("  |  " + $Module.display_name.ToUpper()) -ForegroundColor Magenta
        Write-Host ("  |  MITRE Tactics: " + ($Module.mitre_tactics -join ', ')) -ForegroundColor DarkGray
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ""

        $vectors = @($Module.vectors)

        for ($i = 0; $i -lt $vectors.Count; $i++) {
            $v      = $vectors[$i]
            $stub   = if ($v.type -eq 'not-implemented') { '  [STUB - not yet implemented]' } else { '' }
            $color  = if ($v.type -eq 'not-implemented') { 'DarkGray' } else { 'White' }
            Write-Host ("  [{0}]  {1}{2}" -f ($i + 1), $v.name, $stub) -ForegroundColor $color
            Write-Host ("        $($v.description)") -ForegroundColor DarkGray
            Write-Host ("        MITRE: $($v.mitre)  |  Type: $($v.type)") -ForegroundColor DarkGray
            Write-Host ""
        }

        Write-Host "  [0]   Back to Main Menu" -ForegroundColor Yellow
        Write-Host ""

        $choice = (Read-Host "  Selection").Trim()

        if ($choice -eq '0' -or $choice -eq '') { return }

        $idx = $choice -as [int]
        if ($idx -ge 1 -and $idx -le $vectors.Count) {
            Invoke-SCTVector -Vector $vectors[$idx - 1] `
                -ModuleScriptDir $Module.ScriptDir `
                -Control $Control `
                -SamplesPath $SamplesPath `
                -ResultsPath $ResultsPath `
                -TechResultsPath $TechResultsPath
        } else {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
        }
    }
}

# =============================================================================
# VECTOR EXECUTION DISPATCHER
# =============================================================================

function Invoke-SCTVector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Vector,
        [Parameter(Mandatory)] [string]$ModuleScriptDir,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$SamplesPath,
        [Parameter(Mandatory)] [string]$ResultsPath,
        [Parameter(Mandatory)] [string]$TechResultsPath
    )

    $scriptPath = Join-Path $ModuleScriptDir $Vector.script

    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  VECTOR $($Vector.id): $($Vector.name)" -ForegroundColor Cyan
    Write-Host "  MITRE: $($Vector.mitre)" -ForegroundColor DarkGray
    Write-Host "  ============================================================================" -ForegroundColor Cyan

    # Handle stubs before checking file existence
    if ($Vector.type -eq 'not-implemented') {
        Write-Host ""
        Write-Host "  [i] This vector is not yet implemented." -ForegroundColor Yellow
        Write-Host "  [i] Create the script at: $scriptPath" -ForegroundColor DarkGray
        Write-Host "  [i] Then update 'type' in module.json to the appropriate vector type." -ForegroundColor DarkGray
        Read-Host "`n  Press Enter to return"
        return
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host ""
        Write-Host "  [!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "  [!] Check that module.json 'script' path is correct relative to the module folder." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    switch ($Vector.type) {
        'malware-batch'    { Invoke-MalwareBatchVector   -Vector $Vector -ScriptPath $scriptPath -Control $Control -SamplesPath $SamplesPath -ResultsPath $ResultsPath }
        'removable-media'  { Invoke-RemovableMediaVector -Vector $Vector -ScriptPath $scriptPath -Control $Control -ResultsPath $ResultsPath }
        'client-server'    { Invoke-ClientServerVector   -Vector $Vector -ScriptPath $scriptPath -Control $Control -ResultsPath $ResultsPath }
        'technique'        { Invoke-TechniqueVector      -Vector $Vector -ScriptPath $scriptPath -Control $Control -TechResultsPath $TechResultsPath }
        'simple'           { Invoke-SimpleVector         -Vector $Vector -ScriptPath $scriptPath }
        'fileless'         { Invoke-FilelessVector       -Vector $Vector -ScriptPath $scriptPath -Control $Control -TechResultsPath $TechResultsPath }
        default {
            Write-Host ""
            Write-Host "  [!] Unknown vector type '$($Vector.type)' in module.json." -ForegroundColor Red
            Write-Host "  [!] Valid types: malware-batch, removable-media, client-server, technique, simple, not-implemented" -ForegroundColor DarkGray
            Read-Host "`n  Press Enter to return"
        }
    }
}

# =============================================================================
# TYPE: malware-batch
# Extracts a ZIP from samples/ to C:\Temp\SCT-Staging\, then calls the
# script with -SourcePath and -Control. Supports -DryRun.
# =============================================================================

function Invoke-MalwareBatchVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath, [string]$Control, [string]$SamplesPath, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Delivers and optionally executes malware/tool samples from the samples/ folder." -ForegroundColor White
    Write-Host "  Drop any ZIP of executables into samples/ - no manifest required." -ForegroundColor DarkGray
    Write-Host ""

    $stagingRoot = 'C:\Temp\SCT-Staging'
    $sourcePath  = $null

    # Discover ZIP files in samples/
    $zips = @()
    if (Test-Path $SamplesPath) {
        $zips = @(Get-ChildItem -Path $SamplesPath -Filter '*.zip' -File -ErrorAction SilentlyContinue)
    }

    if ($zips.Count -gt 0) {
        Write-Host "  ZIP archives in samples/:" -ForegroundColor White
        Write-Host ""
        for ($i = 0; $i -lt $zips.Count; $i++) {
            $sz = [math]::Round($zips[$i].Length / 1KB, 0)
            Write-Host ("  [{0}]  {1}  ({2:N0} KB)" -f ($i + 1), $zips[$i].Name, $sz) -ForegroundColor White
        }
        Write-Host ""
        if ($zips.Count -gt 1) {
            Write-Host "  [A]   Run ALL ZIPs together as one batch" -ForegroundColor Yellow
        }
        Write-Host "  [M]   Use an already-extracted folder" -ForegroundColor Yellow
        Write-Host "  [0]   Cancel" -ForegroundColor Yellow
        Write-Host ""

        $hint = if ($zips.Count -gt 1) { "(number), [A] all, [M] folder, [0] cancel" } `
                else                    { "(number), [M] folder, [0] cancel" }
        $zipChoice = (Read-Host "  Select $hint").Trim()

        if ($zipChoice -eq '0' -or $zipChoice -eq '') { return }

        if ($zipChoice -ieq 'A') {
            $zipPassword = (Read-Host "  ZIP password for all archives (press Enter if none)").Trim()
            Write-Host ""
            $sourcePath = Merge-StagingFromZips -Zips $zips -StagingRoot $stagingRoot -Password $zipPassword
        } elseif ($zipChoice -ieq 'M') {
            $sourcePath = (Read-Host "  Full path to already-extracted folder").Trim()
            if (-not $sourcePath) { return }
        } else {
            $zipIdx = $zipChoice -as [int]
            if ($zipIdx -ge 1 -and $zipIdx -le $zips.Count) {
                $chosenZip = $zips[$zipIdx - 1]
                $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($chosenZip.Name)
                $destDir   = Join-Path $stagingRoot $baseName
                $zipPassword = (Read-Host "  ZIP password (press Enter if none)").Trim()
                Write-Host ""
                Write-Host "  [*] Extracting $($chosenZip.Name)..." -ForegroundColor Yellow
                try {
                    Invoke-ZipExtraction -ZipPath $chosenZip.FullName -DestPath $destDir -Password $zipPassword
                } catch {
                    Write-Host "  [!] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                    Read-Host "`n  Press Enter to return"
                    return
                }
                $sourcePath = $destDir
            } else {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                Read-Host "`n  Press Enter to return"
                return
            }
        }
    } else {
        Write-Host "  No ZIP files found in: $SamplesPath" -ForegroundColor Yellow
        Write-Host "  Drop ZIP files into samples/ and re-run, or enter a folder path below." -ForegroundColor DarkGray
        Write-Host ""
        $manual = (Read-Host "  Path to staging folder (or press Enter to cancel)").Trim()
        if (-not $manual) { return }
        $sourcePath = $manual
    }

    if (-not (Test-Path $sourcePath)) {
        Write-Host "  [!] Path does not exist: $sourcePath" -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    Write-Host ""
    $executeInput = (Read-Host "  Execute samples after delivery, not just copy them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to start"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-SourcePath', "`"$sourcePath`"",
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($doExecute) { $scriptArgs += '-Execute' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow

    Write-Host ""
    Write-Host "  [*] Done. Results appended to: $ResultsPath" -ForegroundColor Cyan
    if ($sourcePath -like "$stagingRoot*") {
        Write-Host "  [!] Extracted files remain at: $sourcePath" -ForegroundColor Yellow
        Write-Host "      Delete when review is complete:" -ForegroundColor DarkGray
        Write-Host "      Remove-Item -Recurse -Force '$sourcePath'" -ForegroundColor DarkGray
    }
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# TYPE: removable-media
# Prompts for a drive letter, then calls the script with -DriveLetter -Control.
# =============================================================================

function Invoke-RemovableMediaVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath, [string]$Control, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor White
    Write-Host "    1. Attach a USB drive to this VM" -ForegroundColor DarkGray
    Write-Host "    2. The drive must already contain the sample files - no manifest needed" -ForegroundColor DarkGray
    Write-Host "    3. Load the drive on a separate unprotected machine - NOT this VM" -ForegroundColor DarkGray
    Write-Host "       (Loading from this VM means the control has already scanned them)" -ForegroundColor DarkGray
    Write-Host ""

    $driveLetter = (Read-Host "  Drive letter of removable media (e.g. E:), or press Enter to auto-detect").Trim()

    $executeInput = (Read-Host "  Execute samples after delivery, not just copy them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    $dryRunInput = (Read-Host "  Run as DRY RUN? (detects drive + lists files, no real delivery) [Y/N]").Trim()
    $isDryRun    = $dryRunInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Vector $($Vector.id)"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($driveLetter) { $scriptArgs += @('-DriveLetter', $driveLetter) }
    if ($doExecute)   { $scriptArgs += '-Execute' }
    if ($isDryRun)    { $scriptArgs += '-DryRun' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# TYPE: client-server
# Prompts for server IP/port, calls the victim script with -ServerIP -Control.
# The tester must start the companion server script on a second VM first.
# =============================================================================

function Invoke-ClientServerVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath, [string]$Control, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor White
    Write-Host "    1. Start the companion server script on a second VM first" -ForegroundColor DarkGray
    Write-Host "    2. Both VMs must have network connectivity between them" -ForegroundColor DarkGray
    Write-Host "    3. Confirm the server is listening before continuing" -ForegroundColor DarkGray
    Write-Host ""

    $serverIP = (Read-Host "  IP address of the server VM (e.g. 192.168.1.100)").Trim()
    if (-not $serverIP) {
        Write-Host "  Server IP is required for this vector." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    $portInput = (Read-Host "  Port number [default: 8080]").Trim()
    $port      = if ($portInput) { $portInput } else { '8080' }

    $executeInput = (Read-Host "  Execute samples after download, not just download them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    $dryRunInput = (Read-Host "  Run as DRY RUN? (fetches file listing, no real downloads) [Y/N]").Trim()
    $isDryRun    = $dryRunInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Vector $($Vector.id)"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-ServerIP', $serverIP,
        '-Port', $port,
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($doExecute) { $scriptArgs += '-Execute' }
    if ($isDryRun)  { $scriptArgs += '-DryRun' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# TYPE: technique
# Shows a sub-menu of technique names from module.json, calls the script
# with -Technique <selected>. Used by persistence and priv-esc scripts.
# =============================================================================

function Invoke-TechniqueVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath, [string]$Control, [string]$TechResultsPath)

    $techniques = @($Vector.techniques)

    if ($techniques.Count -eq 0) {
        Write-Host ""
        Write-Host "  [!] No techniques defined in module.json for this vector." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    Write-Host ""
    Write-Host "  Available techniques:" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $techniques.Count; $i++) {
        $t     = $techniques[$i]
        $color = if ($t -eq 'All') { 'Yellow' } else { 'White' }
        Write-Host ("  [{0}]  {1}" -f ($i + 1), $t) -ForegroundColor $color
    }

    Write-Host "  [0]   Cancel" -ForegroundColor DarkGray
    Write-Host ""

    $choice = (Read-Host "  Select technique").Trim()
    if ($choice -eq '0' -or $choice -eq '') { return }

    $idx = $choice -as [int]
    if ($idx -lt 1 -or $idx -gt $techniques.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
        Read-Host "`n  Press Enter to return"
        return
    }

    $technique = $techniques[$idx - 1]

    $markerPattern = $Vector.marker_file
    $individualTechniques = @($Vector.individual_techniques)
    if ($individualTechniques.Count -eq 0) {
        $individualTechniques = @($techniques | Where-Object { $_ -ne 'All' })
    }

    $toCheck = if ($technique -eq 'All') {
        $individualTechniques
    } else {
        @($technique)
    }

    if ($markerPattern) {
        foreach ($t in $toCheck) {
            $markerPath = $markerPattern -replace '\{technique\}', $t
            Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to run: $technique"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-Technique', $technique
    )
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'NoCleanupPrompt') {
        $scriptArgs += '-NoCleanupPrompt'
    }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath -Technique $technique" -ForegroundColor Cyan
    Write-Host ""

    $startTime = Get-Date
    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow

    # Post-run: check marker files and write a result row per technique
    if ($markerPattern -and $TechResultsPath) {
        Write-Host ""
        Write-Host "  [*] Checking results..." -ForegroundColor Cyan
        Write-Host ""

        $executedCount = 0
        foreach ($t in $toCheck) {
            $markerPath = $markerPattern -replace '\{technique\}', $t
            $executed   = Test-SCTMarkerFile -Path $markerPath
            $outcome    = if ($executed) { 'EXECUTED' } else { 'BLOCKED' }
            $notes      = if ($executed) { "marker found: $markerPath" } else { "marker absent after test: $markerPath" }
            $icon       = if ($executed) { '[!]' } else { '[+]' }
            $color      = if ($executed) { 'Red' } else { 'Green' }

            if ($executed) { $executedCount++ }
            Write-Host ("  {0}  {1,-28}  {2}" -f $icon, $t, $outcome) -ForegroundColor $color

            Write-SCTResult -Path $TechResultsPath -Timestamp $startTime -Control $Control `
                -VectorId $Vector.id -VectorName $Vector.name -Technique $t `
                -Outcome $outcome -Notes $notes
        }

        Write-Host ""
        Write-Host "  $executedCount of $($toCheck.Count) techniques executed this run" -ForegroundColor Cyan
        Write-Host "  [i] [!] Red = executed (not blocked by control)" -ForegroundColor DarkGray
        Write-Host "  [i] [+] Green = blocked by control" -ForegroundColor DarkGray
    }

    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# TYPE: simple
# Runs the script directly with no extra parameters. Used for self-contained
# vectors that handle their own prompting (e.g. DLL sideloading, trojanised COTS).
# =============================================================================

function Invoke-SimpleVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath)

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Vector $($Vector.id)"

    $scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"")

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# TYPE: fileless
# Like technique type but aware that some sub-techniques need a remote server
# and some run entirely in local memory. Only prompts for server IP when the
# selected technique is listed in the vector's "remote_techniques" array.
# Nothing is written to disk during execution - no staging folder is created.
# =============================================================================

function Invoke-FilelessVector {
    [CmdletBinding()]
    param($Vector, [string]$ScriptPath, [string]$Control, [string]$TechResultsPath)

    $techniques       = @($Vector.techniques)
    $remoteTechniques = @($Vector.remote_techniques)

    if ($techniques.Count -eq 0) {
        Write-Host ""
        Write-Host "  [!] No techniques defined in module.json for this vector." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    Write-Host ""
    Write-Host "  Execution model: FILELESS - nothing is written to disk." -ForegroundColor Yellow
    Write-Host "  Payloads run entirely in memory (PowerShell process, .NET, WMI, COM)." -ForegroundColor DarkGray
    Write-Host ""

    # Annotate which techniques need a server VM
    Write-Host "  Available techniques:" -ForegroundColor White
    Write-Host ""
    for ($i = 0; $i -lt $techniques.Count; $i++) {
        $t      = $techniques[$i]
        $isAll  = $t -like 'All*'
        $needsServer = $remoteTechniques -contains $t
        $tag    = if ($needsServer)  { '  [needs server VM]' } else { '' }
        $color  = if ($isAll) { 'Yellow' } elseif ($needsServer) { 'Cyan' } else { 'White' }
        Write-Host ("  [{0}]  {1}{2}" -f ($i + 1), $t, $tag) -ForegroundColor $color
    }
    Write-Host "  [0]   Cancel" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Cyan  = requires companion server script on VM2" -ForegroundColor DarkGray
    Write-Host "  White = runs locally, no VM2 needed" -ForegroundColor DarkGray
    Write-Host ""

    $choice = (Read-Host "  Select technique").Trim()
    if ($choice -eq '0' -or $choice -eq '') { return }

    $idx = $choice -as [int]
    if ($idx -lt 1 -or $idx -gt $techniques.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
        Read-Host "`n  Press Enter to return"
        return
    }

    $technique   = $techniques[$idx - 1]
    $individualTechniques = @($techniques | Where-Object { $_ -notlike 'All*' })
    $individualRemoteTechniques = @($remoteTechniques | Where-Object { $_ -notlike 'All*' })
    $toCheck = if ($technique -eq 'All') {
        $individualTechniques
    } elseif ($technique -eq 'AllRemote') {
        $individualRemoteTechniques
    } elseif ($technique -eq 'AllLocal') {
        @($individualTechniques | Where-Object { $individualRemoteTechniques -notcontains $_ })
    } else {
        @($technique)
    }
    $needsServer = ($remoteTechniques -contains $technique) -or (@($toCheck | Where-Object { $remoteTechniques -contains $_ }).Count -gt 0)

    # Only prompt for server IP if the chosen technique actually needs one
    $serverIP = $null
    $port     = '8080'
    if ($needsServer) {
        Write-Host ""
        Write-Host "  '$technique' fetches payloads from a companion server VM at runtime." -ForegroundColor Cyan
        Write-Host "  Start v1.5-server.ps1 on VM2 before continuing." -ForegroundColor DarkGray
        Write-Host ""
        $serverIP = (Read-Host "  IP address of the server VM (e.g. 192.168.1.100)").Trim()
        if (-not $serverIP) {
            Write-Host "  Server IP is required for '$technique'." -ForegroundColor Red
            Read-Host "`n  Press Enter to return"
            return
        }
        $portInput = (Read-Host "  Port number [default: 8080]").Trim()
        if ($portInput) { $port = $portInput }
    } else {
        Write-Host ""
        Write-Host "  '$technique' runs locally - no server VM required." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Write-Host "  [*] No files will be written to disk during this test." -ForegroundColor Yellow
    Read-Host "  Press Enter to run: $technique"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-Technique', $technique
    )
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'NoCleanupPrompt') {
        $scriptArgs += '-NoCleanupPrompt'
    }
    if ($serverIP) {
        $scriptArgs += @('-ServerIP', $serverIP, '-Port', $port)
    }

    foreach ($t in $toCheck) {
        Remove-Item -LiteralPath "C:\Windows\Temp\art-marker-$t.txt" -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath -Technique $technique" -ForegroundColor Cyan
    Write-Host ""

    $startTime = Get-Date
    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow

    # Post-run: check one marker per fileless sub-technique.
    if ($TechResultsPath) {
        Write-Host ""
        Write-Host "  [*] Checking results..." -ForegroundColor Cyan

        $executedCount = 0
        foreach ($t in $toCheck) {
            $markerPath = "C:\Windows\Temp\art-marker-$t.txt"
            $executed = Test-SCTMarkerFile -Path $markerPath
            $outcome = if ($executed) { 'EXECUTED' } else { 'BLOCKED' }
            $notes = if ($executed) { "marker found: $markerPath" } else { "marker absent after test: $markerPath" }
            $icon  = if ($executed) { '[!]' } else { '[+]' }
            $color = if ($executed) { 'Red' } else { 'Green' }

            if ($executed) { $executedCount++ }
            Write-Host ""
            Write-Host ("  {0}  {1,-28}  {2}" -f $icon, $t, $outcome) -ForegroundColor $color
            Write-Host "      $notes" -ForegroundColor DarkGray

            Write-SCTResult -Path $TechResultsPath -Timestamp $startTime -Control $Control `
                -VectorId $Vector.id -VectorName $Vector.name -Technique $t `
                -Outcome $outcome -Notes $notes
        }

        Write-Host ""
        Write-Host "  $executedCount of $($toCheck.Count) techniques executed this run" -ForegroundColor Cyan
        Write-Host "  [i] [!] Red = executed (not blocked by control)" -ForegroundColor DarkGray
        Write-Host "  [i] [+] Green = blocked by control" -ForegroundColor DarkGray
    }

    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# ZIP EXTRACTION
# No-password ZIPs use .NET System.IO.Compression (no dependencies).
# Password-protected ZIPs require 7-Zip - auto-detected from common install
# paths or PATH. Falls back gracefully with a clear error if not found.
# =============================================================================

function Find-7Zip {
    $candidates = @(
        'C:\Program Files\7-Zip\7z.exe',
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $onPath = Get-Command '7z.exe' -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

function Invoke-ZipExtraction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestPath,
        [string]$Password = ''
    )

    if (Test-Path $DestPath) {
        $answer = (Read-Host "  Destination already exists: $DestPath`n  Overwrite? [Y/N]").Trim()
        if ($answer -ine 'Y') {
            Write-Host "  [*] Using existing extraction at: $DestPath" -ForegroundColor Green
            return
        }
        Remove-Item -Path $DestPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $DestPath -Force | Out-Null

    if ($Password) {
        $7zPath = Find-7Zip
        if (-not $7zPath) {
            Write-Host "  [!] 7-Zip is required for password-protected ZIPs but was not found." -ForegroundColor Red
            Write-Host "  [!] Install 7-Zip (7-zip.org), or extract the ZIP manually and use [M]." -ForegroundColor DarkGray
            throw "7-Zip not found. Cannot extract password-protected ZIP without it."
        }
        Write-Host "  [*] Using 7-Zip: $7zPath" -ForegroundColor DarkGray
        & $7zPath x "-p$Password" "-o$DestPath" $ZipPath '-y' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "7-Zip extraction failed (exit $LASTEXITCODE). Verify the password and ZIP file integrity."
        }
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestPath)
    }

    Write-Host "  [+] Extracted to: $DestPath" -ForegroundColor Green
}

# =============================================================================
# MULTI-ZIP STAGING
# Extracts every ZIP in $Zips to its own subfolder under $StagingRoot, then
# copies every file into a single combined-TIMESTAMP folder so v1.1 can test
# them all in one batch. Filenames that collide across ZIPs are prefixed
# with their ZIP's base name to keep them distinct.
# =============================================================================

function Merge-StagingFromZips {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Zips,
        [Parameter(Mandatory)][string]$StagingRoot,
        [string]$Password = ''
    )

    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $combinedDir = Join-Path $StagingRoot "combined-$timestamp"
    New-Item -ItemType Directory -Path $combinedDir -Force | Out-Null

    $seenNames  = @{}
    $totalFiles = 0
    $warnings   = @()

    foreach ($zip in $Zips) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($zip.Name)
        $destDir  = Join-Path $StagingRoot $baseName

        Write-Host "  [*] Extracting $($zip.Name)..." -ForegroundColor Yellow
        try {
            Invoke-ZipExtraction -ZipPath $zip.FullName -DestPath $destDir -Password $Password
        } catch {
            $msg = "Skipped $($zip.Name): $($_.Exception.Message)"
            $warnings += $msg
            Write-Host "  [!] $msg" -ForegroundColor Red
            continue
        }

        $sampleFiles = @(Get-ChildItem -Path $destDir -File)
        Write-Host "    $($sampleFiles.Count) file(s) extracted" -ForegroundColor DarkGray

        foreach ($f in $sampleFiles) {
            # Keep filenames unique across the combined set
            $name = $f.Name
            if ($seenNames.ContainsKey($name)) {
                $newName = "$baseName-$name"
                $warnings += "Duplicate filename '$name' (from $($zip.Name)) renamed to '$newName'"
                $name = $newName
            }
            $seenNames[$name] = $true

            Copy-Item -Path $f.FullName -Destination (Join-Path $combinedDir $name) -Force
            $totalFiles++
        }
    }

    Write-Host ""
    Write-Host "  [+] Combined staging : $combinedDir" -ForegroundColor Green
    Write-Host "  [+] Total samples    : $totalFiles from $($Zips.Count) ZIP(s)" -ForegroundColor Green

    if ($warnings) {
        Write-Host ""
        foreach ($w in $warnings) { Write-Host "  [!] $w" -ForegroundColor Yellow }
    }

    return $combinedDir
}

# =============================================================================
# RESULT WRITER  -  writes one row to technique-results.csv
# All technique and fileless vectors call this after checking their indicators.
# =============================================================================

function Write-SCTResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [datetime]$Timestamp,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$VectorId,
        [Parameter(Mandatory)] [string]$VectorName,
        [Parameter(Mandatory)] [string]$Technique,
        [Parameter(Mandatory)] [ValidateSet('EXECUTED','BLOCKED','NOT-EXPLOITABLE','ERROR')]
        [string]$Outcome,
        [string]$Notes = ''
    )

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    [pscustomobject]@{
        timestamp   = $Timestamp.ToString('o')
        control     = $Control
        vector_id   = $VectorId
        vector_name = $VectorName
        technique   = $Technique
        outcome     = $Outcome
        notes       = $Notes
    } | Export-Csv -Path $Path -Append -NoTypeInformation -Encoding UTF8
}

# =============================================================================
# MARKER FILE CHECK  -  returns $true if the expected marker file exists.
# Invoke-TechniqueVector removes expected markers before launch, so presence
# after the script exits is proof that the current run wrote the marker.
# =============================================================================

function Test-SCTMarkerFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path
    )

    Start-Sleep -Milliseconds 800
    return (Test-Path -LiteralPath $Path)
}

# =============================================================================
# SCRIPT PARAMETER CHECK
# Used by the launcher to opt into newer script parameters without breaking
# older vectors that do not know about them.
# =============================================================================

function Test-SCTScriptSupportsParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ScriptPath,
        [Parameter(Mandatory)] [string]$ParameterName
    )

    try {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0 -or -not $ast.ParamBlock) { return $false }

        $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
            $_.Name.VariablePath.UserPath
        })
        return ($parameterNames -contains $ParameterName)
    } catch {
        return $false
    }
}

# =============================================================================
# CALC.EXE SPAWN CHECK  -  proof-of-execution for fileless vectors.
# Checks Sysmon EID 1 first. If Sysmon is not installed, falls back to a
# manual [E]xecuted / [B]locked / [S]kip prompt so nothing is lost.
# =============================================================================

function Test-SCTCalcSpawned {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [datetime]$After)

    Start-Sleep -Milliseconds 1000
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = 1
            StartTime = $After
        } -ErrorAction Stop

        if ($events | Where-Object { $_.Message -match 'calc\.exe' }) {
            return @{ Outcome = 'EXECUTED'; Notes = 'calc.exe process creation detected via Sysmon EID 1' }
        }
        return @{ Outcome = 'BLOCKED'; Notes = 'calc.exe not detected in Sysmon EID 1 within test window' }
    } catch {
        Write-Host ""
        Write-Host "  Sysmon unavailable for automated detection." -ForegroundColor Yellow
        Write-Host "  Did the technique execute as expected? (e.g. did Calculator open?)" -ForegroundColor White
        Write-Host "  [E] Executed    [B] Blocked    [S] Skip (do not record)" -ForegroundColor DarkGray
        $answer = (Read-Host "  ").Trim().ToUpper()
        switch ($answer) {
            'E' { return @{ Outcome = 'EXECUTED'; Notes = 'manually confirmed by tester - no Sysmon' } }
            'B' { return @{ Outcome = 'BLOCKED';  Notes = 'manually confirmed by tester - no Sysmon' } }
            default { return $null }
        }
    }
}

# =============================================================================
# RESULTS SUMMARY
# Reads both results.csv (malware delivery) and technique-results.csv
# and displays a combined aggregated view.
# =============================================================================

function Show-SCTSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ResultsPath,
        [Parameter(Mandatory)] [string]$TechResultsPath
    )

    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  AGGREGATED TEST RESULTS" -ForegroundColor Cyan
    Write-Host "  ============================================================================" -ForegroundColor Cyan

    $anyData = $false

    # -------------------------------------------------------------------------
    # SECTION 1: Malware delivery results (results.csv)
    # Written by the malware-batch / removable-media / client-server scripts.
    # -------------------------------------------------------------------------
    if (Test-Path $ResultsPath) {
        try {
            $data = Import-Csv -Path $ResultsPath -Encoding UTF8 -ErrorAction Stop
            if ($data) {
                $anyData = $true
                Write-Host ""
                Write-Host "  MALWARE DELIVERY" -ForegroundColor White
                Write-Host ("  " + ('-' * 76)) -ForegroundColor DarkGray

                $hdr = "  {0,-22} {1,-8} {2,-8} {3,-20} {4}"
                Write-Host ($hdr -f 'Control', 'Vector', 'Samples', 'Delivered', 'Sysmon Hit') -ForegroundColor White

                $groups = $data | Group-Object -Property control, vector | Sort-Object Name
                foreach ($g in $groups) {
                    $tot  = $g.Count
                    $del  = ($g.Group | Where-Object { $_.delivery_success   -eq 'True' }).Count
                    $sys  = ($g.Group | Where-Object { $_.sysmon_event_found -eq 'True' }).Count
                    Write-Host ($hdr -f $g.Group[0].control, $g.Group[0].vector, $tot,
                        "$del/$tot ($([math]::Round(100*$del/$tot,0))%)",
                        "$sys/$tot ($([math]::Round(100*$sys/$tot,0))%)"
                    ) -ForegroundColor White
                }

                $tot = $data.Count
                $del = ($data | Where-Object { $_.delivery_success   -eq 'True' }).Count
                $sys = ($data | Where-Object { $_.sysmon_event_found -eq 'True' }).Count
                Write-Host ("  " + ('-' * 76)) -ForegroundColor DarkGray
                Write-Host ($hdr -f 'ALL', 'ALL', $tot,
                    "$del/$tot ($([math]::Round(100*$del/$tot,0))%)",
                    "$sys/$tot ($([math]::Round(100*$sys/$tot,0))%)"
                ) -ForegroundColor Cyan
                Write-Host "  Source: $ResultsPath" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  Could not read $ResultsPath : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # -------------------------------------------------------------------------
    # SECTION 2: Technique and fileless results (technique-results.csv)
    # Written by Invoke-TechniqueVector and Invoke-FilelessVector above.
    # -------------------------------------------------------------------------
    if (Test-Path $TechResultsPath) {
        try {
            $tdata = Import-Csv -Path $TechResultsPath -Encoding UTF8 -ErrorAction Stop
            if ($tdata) {
                $anyData = $true
                Write-Host ""
                Write-Host "  TECHNIQUES & FILELESS" -ForegroundColor White
                Write-Host ("  " + ('-' * 76)) -ForegroundColor DarkGray

                $thdr = "  {0,-10} {1,-20} {2,-8} {3,-26} {4}"
                Write-Host ($thdr -f 'Time', 'Control', 'Vector', 'Technique', 'Outcome') -ForegroundColor White

                foreach ($row in $tdata) {
                    $ts    = try { ([datetime]$row.timestamp).ToString('HH:mm:ss') } catch { '?' }
                    $color = switch ($row.outcome) {
                        'EXECUTED'        { 'Red'    }
                        'BLOCKED'         { 'Green'  }
                        'NOT-EXPLOITABLE' { 'Yellow' }
                        default           { 'Gray'   }
                    }
                    Write-Host ($thdr -f $ts, $row.control, $row.vector_id, $row.technique, $row.outcome) -ForegroundColor $color
                }

                # Per-control summary
                Write-Host ""
                Write-Host ("  " + ('-' * 76)) -ForegroundColor DarkGray
                Write-Host "  TECHNIQUE SUMMARY" -ForegroundColor White
                $shdr = "  {0,-22} {1,-8} {2,-12} {3,-12} {4}"
                Write-Host ($shdr -f 'Control', 'Total', 'Executed', 'Blocked', 'Not-Exploitable') -ForegroundColor White

                $tgroups = $tdata | Group-Object -Property control | Sort-Object Name
                foreach ($g in $tgroups) {
                    $tot   = $g.Count
                    $exec  = ($g.Group | Where-Object { $_.outcome -eq 'EXECUTED'        }).Count
                    $block = ($g.Group | Where-Object { $_.outcome -eq 'BLOCKED'         }).Count
                    $noexp = ($g.Group | Where-Object { $_.outcome -eq 'NOT-EXPLOITABLE' }).Count
                    Write-Host ($shdr -f $g.Name, $tot, "$exec/$tot", "$block/$tot", $noexp) -ForegroundColor White
                }

                Write-Host "  Source: $TechResultsPath" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  Could not read $TechResultsPath : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if (-not $anyData) {
        Write-Host ""
        Write-Host "  No results found yet. Run some tests first." -ForegroundColor Yellow
        Write-Host "  Delivery results will appear at : $ResultsPath" -ForegroundColor DarkGray
        Write-Host "  Technique results will appear at: $TechResultsPath" -ForegroundColor DarkGray
    }

    Write-Host ""
    Read-Host "  Press Enter to return"
}
