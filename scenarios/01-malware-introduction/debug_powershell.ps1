$taskName = "TestTask_$(Get-Random)"

# --- Test 1: Scheduled Task Creation Permission ---
Write-Host "`n[TEST 1] Scheduled Task Creation" -ForegroundColor Cyan
try {
    $action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo hello"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $task    = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -ErrorAction Stop
    Write-Host "  PASS: Scheduled task '$taskName' created successfully." -ForegroundColor Green
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  CLEAN: Task removed." -ForegroundColor DarkGray
} catch {
    Write-Host "  FAIL: $($_.Exception.Message)" -ForegroundColor Red
}

# --- Test 2: COM Object Creation ---
Write-Host "`n[TEST 2] COM Object Creation" -ForegroundColor Cyan
$comTests = @(
    @{ Name = "WScript.Shell";         ProgId = "WScript.Shell" },
    @{ Name = "Shell.Application";     ProgId = "Shell.Application" },
    @{ Name = "Scripting.FileSystemObject"; ProgId = "Scripting.FileSystemObject" }
)
foreach ($c in $comTests) {
    try {
        $obj = New-Object -ComObject $c.ProgId -ErrorAction Stop
        Write-Host "  PASS: Created COM object '$($c.Name)'" -ForegroundColor Green
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) | Out-Null
    } catch {
        Write-Host "  FAIL [$($c.Name)]: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Test 3: .NET Process Creation ---
Write-Host "`n[TEST 3] .NET Process Creation (System.Diagnostics.Process)" -ForegroundColor Cyan
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = "cmd.exe"
    $psi.Arguments              = "/c echo dotnet-process-test"
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $output = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    Write-Host "  PASS: Process exited with code $($proc.ExitCode). Output: $($output.Trim())" -ForegroundColor Green
} catch {
    Write-Host "  FAIL: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan
