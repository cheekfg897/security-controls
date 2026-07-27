<#
.SYNOPSIS
    Technique 4.4: WMI Event Subscription Persistence (T1546.003)

.DESCRIPTION
    Two subtests adapted from Atomic Red Team T1546.003. Each subtest creates a
    permanent WMI event filter, consumer, and filter-to-consumer binding in
    root\subscription. A short-lived ping.exe process triggers the subscription,
    and the consumer writes a benign marker to C:\Windows\Temp.

    The WMI objects are removed in a finally block immediately after each
    subtest. Marker files remain for SCT result collection and optional cleanup.

    Subtest 1 (CommandLineConsumer) - CommandLineEventConsumer launches cmd.exe
                                      to write the marker.

    Subtest 2 (ActiveScriptConsumer)- ActiveScriptEventConsumer runs VBScript
                                      that writes the marker directly.

    Administrator privileges are required to create permanent WMI subscriptions.

.PARAMETER Subtest
    Which subtest to run. Use 'All' to run both sequentially.
    Default: CommandLineConsumer.

.EXAMPLE
    .\v4.4-wmi-event-subscription.ps1 -Subtest CommandLineConsumer
    .\v4.4-wmi-event-subscription.ps1 -Subtest All
#>

param(
    [ValidateSet('CommandLineConsumer','ActiveScriptConsumer','All')]
    [Alias('Technique')]
    [string]$Subtest = 'CommandLineConsumer',
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly
)

$tempDir = 'C:\Windows\Temp'
$subscriptionNamespace = 'root\subscription'
$triggerExecutable = Join-Path $env:SystemRoot 'System32\PING.EXE'

$subscriptionNames = @{
    CommandLineConsumer = 'SCT-WMI-CommandLineConsumer'
    ActiveScriptConsumer = 'SCT-WMI-ActiveScriptConsumer'
}

# ==============================================================================
# HELPERS
# ==============================================================================

function Write-Header {
    param([string]$Title, [string]$Detection)
    Write-Host ("`n" + ("=" * 90)) -ForegroundColor Magenta
    Write-Host "  SUBTEST: $Title" -ForegroundColor Magenta
    Write-Host "  DETECTION DIFFICULTY: $Detection" -ForegroundColor Magenta
    Write-Host ("=" * 90) -ForegroundColor Magenta
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-MarkerPath {
    param([string]$Name)
    return (Join-Path $tempDir "art-v4.4-$Name.txt")
}

function Remove-SCTWmiSubscription {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [switch]$Quiet
    )

    $escapedName = $Name.Replace("'", "''")
    $errors = @()

    foreach ($consumerClass in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        try {
            $consumers = @(Get-WmiObject -Namespace $subscriptionNamespace -Class $consumerClass `
                -Filter "Name='$escapedName'" -ErrorAction Stop)

            foreach ($consumer in $consumers) {
                $bindings = @(Get-WmiObject -Namespace $subscriptionNamespace `
                    -Query "REFERENCES OF {$($consumer.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding" `
                    -ErrorAction Stop)
                foreach ($binding in $bindings) {
                    Remove-WmiObject -InputObject $binding -ErrorAction Stop
                }
                Remove-WmiObject -InputObject $consumer -ErrorAction Stop
            }
        } catch {
            $errors += $_.Exception.Message
        }
    }

    try {
        $filters = @(Get-WmiObject -Namespace $subscriptionNamespace -Class '__EventFilter' `
            -Filter "Name='$escapedName'" -ErrorAction Stop)
        foreach ($filter in $filters) {
            Remove-WmiObject -InputObject $filter -ErrorAction Stop
        }
    } catch {
        $errors += $_.Exception.Message
    }

    if (-not $Quiet) {
        if ($errors.Count -eq 0) {
            Write-Host "    Removed WMI subscription objects: $Name" -ForegroundColor DarkGray
        } else {
            Write-Host "    WMI cleanup warning for '$Name': $($errors -join ' | ')" -ForegroundColor Yellow
        }
    }
}

function Wait-SCTMarker {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [int]$TimeoutSeconds = 12
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $Path) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    return $false
}

function Invoke-SCTWmiConsumer {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$ConsumerClass,
        [Parameter(Mandatory)] [hashtable]$ConsumerProperties,
        [Parameter(Mandatory)] [string]$MarkerPath
    )

    if (-not (Test-Administrator)) {
        Write-Host "  RESULT: Administrator privileges are required for permanent WMI subscriptions." -ForegroundColor Red
        return $false
    }

    if (-not (Test-Path -LiteralPath $triggerExecutable -PathType Leaf)) {
        Write-Host "  RESULT: Trigger executable not found: $triggerExecutable" -ForegroundColor Red
        return $false
    }

    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Ignore
    Remove-SCTWmiSubscription -Name $Name -Quiet

    $triggerProcess = $null
    try {
        $filterProperties = @{
            Name = $Name
            EventNameSpace = 'root\CimV2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'PING.EXE'"
        }

        Write-Host "`n[*] Creating permanent WMI event filter..." -ForegroundColor Yellow
        Write-Host "    Namespace : $subscriptionNamespace" -ForegroundColor DarkGray
        Write-Host "    Name      : $Name" -ForegroundColor DarkGray
        Write-Host "    Trigger   : New PING.EXE process" -ForegroundColor DarkGray
        $filter = New-CimInstance -Namespace $subscriptionNamespace -ClassName '__EventFilter' `
            -Property $filterProperties -ErrorAction Stop

        Write-Host "[*] Creating $ConsumerClass..." -ForegroundColor Yellow
        $consumer = New-CimInstance -Namespace $subscriptionNamespace -ClassName $ConsumerClass `
            -Property $ConsumerProperties -ErrorAction Stop

        Write-Host "[*] Binding event filter to consumer..." -ForegroundColor Yellow
        $bindingProperties = @{
            Filter = [ref]$filter
            Consumer = [ref]$consumer
        }
        [void](New-CimInstance -Namespace $subscriptionNamespace -ClassName '__FilterToConsumerBinding' `
            -Property $bindingProperties -ErrorAction Stop)

        Write-Host "[*] Starting a short-lived ping.exe trigger..." -ForegroundColor Yellow
        $triggerProcess = Start-Process -FilePath $triggerExecutable `
            -ArgumentList @('-n', '10', '-w', '1000', '127.0.0.1') `
            -WindowStyle Hidden -PassThru -ErrorAction Stop

        if (Wait-SCTMarker -Path $MarkerPath) {
            Write-Host "[+] SUCCESS: WMI consumer executed - $MarkerPath" -ForegroundColor Green
            return $true
        }

        Write-Host "[-] FAILED: Marker was not created (consumer blocked or unsupported)." -ForegroundColor Red
        return $false
    } catch {
        Write-Host "  RESULT: WMI subscription creation or execution failed - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        if ($null -ne $triggerProcess -and -not $triggerProcess.HasExited) {
            Stop-Process -Id $triggerProcess.Id -Force -ErrorAction Ignore
        }
        Write-Host "[*] Removing permanent WMI subscription objects..." -ForegroundColor Yellow
        Remove-SCTWmiSubscription -Name $Name
    }
}

function Invoke-Cleanup {
    param([string[]]$Names)

    foreach ($name in $Names) {
        Remove-SCTWmiSubscription -Name $subscriptionNames[$name] -Quiet
        Remove-Item -LiteralPath (Get-MarkerPath -Name $name) -Force -ErrorAction Ignore
    }
    Write-Host '[+] Cleanup complete' -ForegroundColor Green
}

# ==============================================================================
# SUBTEST 1: CommandLineEventConsumer
# Atomic Red Team: T1546.003 - CommandLineEventConsumer
# ==============================================================================

function Test-CommandLineConsumer {
    Write-Header 'Permanent WMI CommandLineEventConsumer' 'HIGH'
    Write-Host "`nMethod : Create an __EventFilter and CommandLineEventConsumer in root\subscription."
    Write-Host '         A new ping.exe process triggers cmd.exe as SYSTEM to write the marker.'
    Write-Host '         The binding, consumer, and filter are removed after verification.'
    Write-Host "`nDetection:"
    Write-Host '  Sysmon 19 - WmiEventFilter activity'
    Write-Host '  Sysmon 20 - WmiEventConsumer activity'
    Write-Host '  Sysmon 21 - WmiEventConsumerToFilter activity'
    Write-Host '  Process   - WmiPrvSE.exe spawning cmd.exe'

    $name = $subscriptionNames.CommandLineConsumer
    $marker = Get-MarkerPath -Name 'CommandLineConsumer'
    $consumerProperties = @{
        Name = $name
        ExecutablePath = $env:ComSpec
        CommandLineTemplate = "$env:ComSpec /d /c echo SCT WMI CommandLineConsumer triggered> `"$marker`""
    }

    return (Invoke-SCTWmiConsumer -Name $name -ConsumerClass 'CommandLineEventConsumer' `
        -ConsumerProperties $consumerProperties -MarkerPath $marker)
}

# ==============================================================================
# SUBTEST 2: ActiveScriptEventConsumer
# Atomic Red Team: T1546.003 - ActiveScriptEventConsumer
# ==============================================================================

function Test-ActiveScriptConsumer {
    Write-Header 'Permanent WMI ActiveScriptEventConsumer' 'HIGH'
    Write-Host "`nMethod : Create an __EventFilter and ActiveScriptEventConsumer in root\subscription."
    Write-Host '         A new ping.exe process triggers VBScript as SYSTEM to write the marker.'
    Write-Host '         The binding, consumer, and filter are removed after verification.'
    Write-Host "`nDetection:"
    Write-Host '  Sysmon 19 - WmiEventFilter activity'
    Write-Host '  Sysmon 20 - WmiEventConsumer activity'
    Write-Host '  Sysmon 21 - WmiEventConsumerToFilter activity'
    Write-Host '  Process   - scrcons.exe hosting an ActiveScriptEventConsumer'

    $name = $subscriptionNames.ActiveScriptConsumer
    $marker = Get-MarkerPath -Name 'ActiveScriptConsumer'
    $scriptText = @"
Set fso = CreateObject("Scripting.FileSystemObject")
Set marker = fso.CreateTextFile("$marker", True)
marker.WriteLine "SCT WMI ActiveScriptConsumer triggered"
marker.Close
"@
    $consumerProperties = @{
        Name = $name
        ScriptingEngine = 'VBScript'
        ScriptText = $scriptText
    }

    return (Invoke-SCTWmiConsumer -Name $name -ConsumerClass 'ActiveScriptEventConsumer' `
        -ConsumerProperties $consumerProperties -MarkerPath $marker)
}

# ==============================================================================
# RUN AND REPORT
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host '|   WMI EVENT SUBSCRIPTION PERSISTENCE - ALL SUBTESTS                         |' -ForegroundColor Cyan
    Write-Host '+==============================================================================+' -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'CommandLineConsumer'; Fn = ${function:Test-CommandLineConsumer} },
        @{ Name = 'ActiveScriptConsumer'; Fn = ${function:Test-ActiveScriptConsumer} }
    )

    $results = @()
    foreach ($test in $tests) {
        $results += @{ Name = $test.Name; Success = (& $test.Fn) }
        if (-not $NoPause) {
            Write-Host "`n[!] Check EDR/AV console before continuing." -ForegroundColor Yellow
            [void](Read-Host '    Press Enter for next subtest')
        }
    }
    return $results
}

function Write-Report {
    param([array]$Results)

    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host '|                         EXECUTION REPORT                                    |' -ForegroundColor Cyan
    Write-Host '+==============================================================================+' -ForegroundColor Cyan
    foreach ($result in $Results) {
        $label = if ($result.Success) { 'EXECUTED' } else { 'BLOCKED ' }
        $color = if ($result.Success) { 'Green' } else { 'Red' }
        Write-Host "  [$label] $($result.Name)" -ForegroundColor $color
    }
    $executed = @($Results | Where-Object { $_.Success }).Count
    Write-Host "`n  $executed of $($Results.Count) subtests executed successfully" -ForegroundColor Cyan
}

$allSubtests = @('CommandLineConsumer', 'ActiveScriptConsumer')

if ($CleanupOnly) {
    Invoke-Cleanup -Names $allSubtests
    exit 0
}

Write-Host "`n[TEST] WMI Event Subscription Persistence (Technique 4.4)" -ForegroundColor Cyan
Write-Host "  MITRE: T1546.003  |  Phase 4  |  Persistence`n"

switch ($Subtest) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] WMI subscriptions were removed; marker files remain in $tempDir for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $choice = Read-Host 'Clean marker files now? (Y/N)'
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                Invoke-Cleanup -Names $allSubtests
            }
        }
    }
    default {
        Write-Host '+==============================================================================+' -ForegroundColor Cyan
        Write-Host "|   SINGLE SUBTEST: $Subtest" -ForegroundColor Cyan
        Write-Host '+==============================================================================+' -ForegroundColor Cyan
        if (-not $NoPause) {
            Write-Host "`n[!] Have the EDR/AV console visible before proceeding." -ForegroundColor Yellow
            [void](Read-Host '    Press Enter to start')
        }

        $success = switch ($Subtest) {
            'CommandLineConsumer' { Test-CommandLineConsumer }
            'ActiveScriptConsumer' { Test-ActiveScriptConsumer }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        $outcome = if ($success) { 'EXECUTED' } else { 'BLOCKED' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $outcome" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $choice = Read-Host 'Clean marker file now? (Y/N)'
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                Invoke-Cleanup -Names @($Subtest)
            }
        }
    }
}
