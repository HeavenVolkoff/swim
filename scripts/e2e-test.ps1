# End-to-End Windows Installer (MSI) test script for swim.
# Executed on Windows runners (Windows Server and Windows 11 ARM64).

param(
    [Parameter(Mandatory=$true)]
    [Alias("SwimPath")]
    [string]$SwimPath,
    [Parameter(Mandatory=$true)]
    [ValidateSet("x64", "arm64", "x86")]
    [string]$TargetArch
)

$ErrorActionPreference = "Stop"

$OSInfo = [System.Environment]::OSVersion.VersionString
$MachineArch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
Write-Host "=== Starting E2E Tests on $OSInfo ($MachineArch) for Target: $TargetArch ==="

$TempDir = "$env:TEMP\swim_e2e_$(Get-Random)"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

$CertSubject = "Test RSA Code Signing"
$CertPath = "test_fixtures/certs/rsa_codesign.pem"
$KeyPath = "test_fixtures/certs/rsa_codesign.key"

try {
    # 1. Temporarily install test root certificate for Authenticode verification
    Write-Host "[*] Adding test root certificate to LocalMachine\Root..."
    certutil -addstore -f Root $CertPath | Out-Null

    # 2. Incompatible architecture check
    # If this machine is AMD64 (x64) and target is arm64, msiexec must reject with error 1633.
    if ($MachineArch -eq "AMD64" -and $TargetArch -eq "arm64") {
        Write-Host "[*] Testing incompatible architecture rejection (arm64 on AMD64)..."
        $IncompatibleMsi = "$TempDir\incompatible_arm64.msi"
        & $SwimPath -n "IncompatApp" test_fixtures/mock.exe -o $IncompatibleMsi -a arm64 -s machine
        if ($LASTEXITCODE -ne 0) { throw "swim failed to build incompatible package" }

        $ArgsList = "/i `"$IncompatibleMsi`" /qn"
        $Proc = Start-Process msiexec.exe -ArgumentList $ArgsList -Wait -PassThru
        if ($Proc.ExitCode -ne 1633) {
            throw "Expected exit code 1633 (ERROR_INSTALL_PLATFORM_UNSUPPORTED), " +
                "got: $($Proc.ExitCode)"
        }
        Write-Host "[+] Incompatible architecture properly rejected with exit code 1633"
        return
    }

    # 3. Build signed package with multiple files, icon, and license
    Write-Host "[*] Building multi-file signed MSI package..."
    $MsiPath = "$TempDir\E2ETestApp.msi"
    $Files = @(
        "test_fixtures/mock.exe",
        "test_fixtures/mock.dll:bin/mock.dll",
        "test_fixtures/readme.txt:docs/readme.txt"
    )
    & $SwimPath -n "E2ETestApp" -v "1.0.0.0" -m "TestPublisher" -a $TargetArch -s machine `
        -i test_fixtures/app.ico -l test_fixtures/LICENSE.txt $Files `
        --sign-cert $CertPath --sign-key $KeyPath --sign-desc "E2E Test Suite" `
        --timestamp 1700000000 -o $MsiPath

    if ($LASTEXITCODE -ne 0) { throw "swim build failed with exit code $LASTEXITCODE" }

    # 4. Verify outer MSI signature with Windows CryptoAPI
    Write-Host "[*] Validating outer MSI Authenticode signature..."
    $MsiSig = Get-AuthenticodeSignature $MsiPath
    if ($MsiSig.Status -ne "Valid") {
        throw "MSI signature is not Valid: $($MsiSig.Status) ($($MsiSig.StatusMessage))"
    }
    Write-Host "[+] MSI Authenticode Signature Valid"

    # 5. Install silently with logging
    Write-Host "[*] Installing package silently via msiexec.exe..."
    $LogFile = "$TempDir\install.log"
    $InstallArgs = "/i `"$MsiPath`" /qn /l*v `"$LogFile`""
    $Proc = Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru
    if ($Proc.ExitCode -ne 0) {
        Get-Content $LogFile | Select-Object -Last 60
        throw "msiexec install failed with code $($Proc.ExitCode)"
    }
    Write-Host "[+] Installation succeeded (code 0)"

    # Determine standard installation root
    $InstallFolder = if ($TargetArch -eq "x86" -and $MachineArch -eq "AMD64") {
        "C:\Program Files (x86)\E2ETestApp"
    } else {
        "C:\Program Files\E2ETestApp"
    }

    # 6. Verify installed files and auto-signed PE signatures
    Write-Host "[*] Verifying installed files on disk..."
    $MainExe = "$InstallFolder\mock.exe"
    $NestedDll = "$InstallFolder\bin\mock.dll"
    $NestedDoc = "$InstallFolder\docs\readme.txt"

    foreach ($file in @($MainExe, $NestedDll, $NestedDoc)) {
        if (!(Test-Path $file)) { throw "Expected installed file missing: $file" }
    }

    Write-Host "[*] Verifying auto-signed PE signatures on disk..."
    $ExeSig = Get-AuthenticodeSignature $MainExe
    if ($ExeSig.Status -ne "Valid") {
        throw "Auto-signed main executable signature not Valid: $($ExeSig.Status)"
    }
    $DllSig = Get-AuthenticodeSignature $NestedDll
    if ($DllSig.Status -ne "Valid") {
        throw "Auto-signed nested DLL signature not Valid: $($DllSig.Status)"
    }
    Write-Host "[+] Auto-signed payload PE files are Valid on disk"

    # 7. Verify shortcuts created by default
    $DeskLnk = "C:\Users\Public\Desktop\E2ETestApp.lnk"
    $MenuLnk = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\E2ETestApp.lnk"
    if (!(Test-Path $DeskLnk)) { throw "Desktop shortcut missing: $DeskLnk" }
    if (!(Test-Path $MenuLnk)) { throw "Start Menu shortcut missing: $MenuLnk" }
    Write-Host "[+] Default shortcuts created successfully"

    # 8. Clean uninstallation
    Write-Host "[*] Uninstalling package..."
    $Uninst = Start-Process msiexec.exe -ArgumentList "/x `"$MsiPath`" /qn" -Wait -PassThru
    if ($Uninst.ExitCode -ne 0) { throw "msiexec uninstall failed with code $($Uninst.ExitCode)" }
    if (Test-Path $MainExe) { throw "Installed file remained after uninstall: $MainExe" }
    if (Test-Path $DeskLnk) { throw "Desktop shortcut remained after uninstall: $DeskLnk" }
    Write-Host "[+] Uninstallation verified clean"

    # 9. Test shortcut opt-out property (DESKTOPSHORTCUT=0)
    Write-Host "[*] Testing shortcut suppression (DESKTOPSHORTCUT=0)..."
    $OptOutArgs = "/i `"$MsiPath`" DESKTOPSHORTCUT=0 /qn"
    $ProcNoDesk = Start-Process msiexec.exe -ArgumentList $OptOutArgs -Wait -PassThru
    if ($ProcNoDesk.ExitCode -ne 0) { throw "Install failed with DESKTOPSHORTCUT=0" }
    if (Test-Path $DeskLnk) { throw "Desktop shortcut created despite DESKTOPSHORTCUT=0" }
    if (!(Test-Path $MenuLnk)) { throw "Start Menu shortcut missing when DESKTOPSHORTCUT=0" }
    Start-Process msiexec.exe -ArgumentList "/x `"$MsiPath`" /qn" -Wait | Out-Null
    Write-Host "[+] Desktop shortcut suppression verified"

} finally {
    certutil -delstore Root $CertSubject | Out-Null
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "=== E2E Test Run Completed for $TargetArch ==="
}
