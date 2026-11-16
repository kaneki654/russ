@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "RUSS_BUILD_SCRIPT=%~f0"
set "RUSS_BUILD_ROOT=%~dp0"
set "RUSS_BUILD_RUN=0"
set "RUSS_BUILD_NO_PAUSE=0"

:arguments
if "%~1"=="" goto setup
if /I "%~1"=="--run" goto run_option
if /I "%~1"=="--no-pause" goto no_pause_option
if /I "%~1"=="--help" goto help
echo Unknown option. Use build-windows.bat --help.
exit /b 2

:run_option
set "RUSS_BUILD_RUN=1"
shift
goto arguments

:no_pause_option
set "RUSS_BUILD_NO_PAUSE=1"
shift
goto arguments

:help
echo Usage: build-windows.bat [--run] [--no-pause]
echo Installs missing build prerequisites and builds the Windows x64 RUSS app.
echo --run       Launch RUSS after a successful build.
echo --no-pause  Exit without waiting for a keypress, for terminals and CI.
exit /b 0

:setup
if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" goto missing_powershell
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$parts = [IO.File]::ReadAllText($env:RUSS_BUILD_SCRIPT) -split '(?m)^# RUSS_SETUP_POWERSHELL\r?$', 2; if ($parts.Length -ne 2) { throw 'Invalid RUSS build script' }; & ([ScriptBlock]::Create($parts[1]))"
set "RUSS_BUILD_EXIT=%ERRORLEVEL%"
if not "%RUSS_BUILD_NO_PAUSE%"=="1" pause
exit /b %RUSS_BUILD_EXIT%

:missing_powershell
echo Windows PowerShell 5.1 is required. This script supports Windows 10/11 x64.
if not "%RUSS_BUILD_NO_PAUSE%"=="1" pause
exit /b 1

# RUSS_SETUP_POWERSHELL
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$russTarget = 'x86_64-pc-windows-msvc'
$russToolchain = 'stable-x86_64-pc-windows-msvc'
$script:russScratch = $null
$script:russExitCode = 0

function Get-SetupScratch {
    if (-not $script:russScratch) {
        $directory = Join-Path ([IO.Path]::GetTempPath()) ('russ-setup-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $script:russScratch = $directory
    }
    return $script:russScratch
}

function Receive-Installer([string]$Uri, [string]$FileName) {
    $destination = Join-Path (Get-SetupScratch) $FileName
    Write-Host ('Downloading ' + $FileName + '...')
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $destination -TimeoutSec 180
            return $destination
        } catch {
            if ($attempt -eq 3) { throw }
            Write-Warning ('Download failed; retrying (' + $attempt + '/3).')
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

function Invoke-Tool([string]$Executable, [string[]]$ToolArguments, [string]$Description) {
    & $Executable @ToolArguments
    if ($LASTEXITCODE -ne 0) {
        throw ($Description + ' failed with exit code ' + $LASTEXITCODE + '. Check the output above.')
    }
}

function Find-VisualStudio {
    $programFiles = [Environment]::GetFolderPath('ProgramFilesX86')
    $vswhere = Join-Path $programFiles 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -eq 0 -and $installation) {
            return ([string]$installation).Trim()
        }
    }
    return $null
}

function Import-CompilerEnvironment([string]$Installation) {
    $vcvars = Join-Path $Installation 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars)) { return $false }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $env:ComSpec
    $info.Arguments = '/d /u /s /c ""' + $vcvars + '" >nul && set"'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::Unicode
    $info.StandardErrorEncoding = [Text.Encoding]::Unicode
    $process = [Diagnostics.Process]::Start($info)
    try {
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $outputTask.GetAwaiter().GetResult()
        $diagnostic = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            Write-Warning ('Could not load the Visual Studio environment: ' + $diagnostic.Trim())
            return $false
        }
        foreach ($line in ($output -split '\r?\n')) {
            if ($line -match '^([^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            }
        }
        return $true
    } finally {
        $process.Dispose()
    }
}

function Test-CompilerTools {
    foreach ($tool in @('cl.exe', 'link.exe', 'rc.exe')) {
        if (-not (Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) {
            return $false
        }
    }
    # These tools can also be found in unrelated programs' PATH entries.
    # Require the SDK and MSVC library environment, not only executable names.
    return (-not [string]::IsNullOrWhiteSpace($env:VCINSTALLDIR)) -and
        (-not [string]::IsNullOrWhiteSpace($env:WindowsSdkDir)) -and
        (-not [string]::IsNullOrWhiteSpace($env:LIB))
}

function Install-CompilerTools {
    Write-Host 'Installing Microsoft C++ Build Tools and the Windows SDK. Windows may ask for administrator approval.'
    $installer = Receive-Installer 'https://aka.ms/vs/17/release/vs_buildtools.exe' 'vs_buildtools.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
        throw 'Microsoft installer signature verification failed. The installer was not executed.'
    }
    $installation = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\2022\BuildTools'
    $vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $existingBuildTools = & $vswhere -latest -products Microsoft.VisualStudio.Product.BuildTools -version '[17.0,18.0)' -property installationPath
        if ($LASTEXITCODE -eq 0 -and $existingBuildTools) {
            $installation = ([string]$existingBuildTools).Trim()
        }
    }
    $installerArguments = @()
    if (Test-Path -LiteralPath (Join-Path $installation 'Common7\Tools')) {
        $installerArguments += @('modify', '--channelId', 'VisualStudio.17.Release')
    }
    $installerArguments += @('--passive', '--wait', '--norestart', '--installPath', ('"' + $installation + '"'),
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621')
    $options = @{ FilePath = $installer; ArgumentList = $installerArguments; Wait = $true; PassThru = $true }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $options.Verb = 'RunAs'
    }
    $process = Start-Process @options
    try {
        if ($process.ExitCode -eq 3010 -or $process.ExitCode -eq 1641) {
            $script:russExitCode = 3010
            throw 'Microsoft Build Tools requires a Windows restart. Restart Windows and run this batch file again.'
        }
        if ($process.ExitCode -ne 0) {
            throw ('Microsoft Build Tools installation failed with exit code ' + $process.ExitCode + '.')
        }
    } finally {
        $process.Dispose()
    }
    return $installation
}

function Add-CargoPath([string]$CargoBin) {
    $env:Path = $CargoBin + ';' + $env:Path
    # Preserve the existing PATH text and registry value type; never use setx,
    # which can expand or truncate an existing PATH on older Windows versions.
    $registry = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $rawPath = [string]$registry.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $entries = [Environment]::ExpandEnvironmentVariables($rawPath) -split ';'
        $alreadyPresent = @($entries | Where-Object { $_.Trim().TrimEnd('\') -ieq $CargoBin.TrimEnd('\') }).Count -gt 0
        if ($alreadyPresent) { return }
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($registry.GetValueNames() -contains 'Path') {
            $kind = $registry.GetValueKind('Path')
            if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String -and
                $kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                throw 'User PATH has an unexpected registry type; it has not been changed.'
            }
        }
        $updated = $CargoBin
        if ($rawPath) { $updated += ';' + $rawPath }
        $registry.SetValue('Path', $updated, $kind)
    } finally {
        $registry.Dispose()
    }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RussSetupEnvironment {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr window, uint message,
        UIntPtr wparam, string lparam, uint flags, uint timeout, out UIntPtr result);
}
'@
        $broadcastResult = [UIntPtr]::Zero
        $null = [RussSetupEnvironment]::SendMessageTimeout([IntPtr]0xffff, 0x1a,
            [UIntPtr]::Zero, 'Environment', 2, 1000, [ref]$broadcastResult)
    } catch {
        Write-Warning 'Cargo PATH was saved. Sign out and back in if other terminals do not see it yet.'
    }
}

try {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
    if ($architecture -ne 'AMD64' -or -not [Environment]::Is64BitOperatingSystem -or
        [Environment]::OSVersion.Version.Major -lt 10) {
        throw 'This build script requires Windows 10 or Windows 11 on an x64 computer.'
    }
    $root = $env:RUSS_BUILD_ROOT
    if (-not (Test-Path -LiteralPath (Join-Path $root 'Cargo.toml')) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'src\main.rs'))) {
        throw 'Keep build-windows.bat in the complete RUSS source folder, beside Cargo.toml.'
    }
    Set-Location -LiteralPath $root
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Host 'RUSS - Windows setup and release build'
    Write-Host '[1/3] Checking Microsoft C++ tools and Windows SDK...'
    $visualStudio = Find-VisualStudio
    if ($visualStudio) { $null = Import-CompilerEnvironment $visualStudio }
    if (-not (Test-CompilerTools)) {
        $visualStudio = Install-CompilerTools
        if (-not $visualStudio) { throw 'C++ tools were not detected after installation. Check the Visual Studio Installer.' }
        $null = Import-CompilerEnvironment $visualStudio
        if (-not (Test-CompilerTools)) { throw 'C++ compiler, linker or SDK resource compiler is still missing after setup.' }
    }
    Write-Host '[2/3] Checking Rust and Cargo...'
    $cargoHome = $env:CARGO_HOME
    if (-not $cargoHome) { $cargoHome = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cargo' }
    $cargoBin = [IO.Path]::GetFullPath((Join-Path $cargoHome 'bin'))
    $rustup = Join-Path $cargoBin 'rustup.exe'
    $cargo = Join-Path $cargoBin 'cargo.exe'
    $rustc = Join-Path $cargoBin 'rustc.exe'
    # Reuse a rustup installation provided by another package manager when
    # all three proxies are together, rather than installing a second copy.
    if (-not (Test-Path -LiteralPath $rustup)) {
        $existing = Get-Command rustup.exe -CommandType Application -ErrorAction SilentlyContinue
        if ($existing) {
            $existingBin = Split-Path -Parent $existing.Source
            if ((Test-Path -LiteralPath (Join-Path $existingBin 'cargo.exe')) -and
                (Test-Path -LiteralPath (Join-Path $existingBin 'rustc.exe'))) {
                $cargoBin = $existingBin
                $rustup = Join-Path $cargoBin 'rustup.exe'
                $cargo = Join-Path $cargoBin 'cargo.exe'
                $rustc = Join-Path $cargoBin 'rustc.exe'
            }
        }
    }
    if (-not (Test-Path -LiteralPath $rustup) -or -not (Test-Path -LiteralPath $cargo) -or
        -not (Test-Path -LiteralPath $rustc)) {
        $uri = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
        $installer = Receive-Installer $uri 'rustup-init.exe'
        $checksum = Receive-Installer ($uri + '.sha256') 'rustup-init.exe.sha256'
        $checksumText = Get-Content -LiteralPath $checksum -Raw
        if ($checksumText -notmatch '^\s*([0-9a-fA-F]{64})(?:\s|$)') { throw 'Invalid Rust installer checksum file.' }
        $expectedHash = $Matches[1]
        if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ine $expectedHash) {
            throw 'Rust installer checksum verification failed. The installer was not executed.'
        }
        Invoke-Tool $installer @('-y', '--profile', 'minimal', '--default-host', $russTarget,
            '--default-toolchain', 'stable', '--no-modify-path') 'Rust installation'
    }
    Add-CargoPath $cargoBin
    Invoke-Tool $rustup @('toolchain', 'install', $russToolchain, '--profile', 'minimal', '--no-self-update') 'Stable Rust toolchain setup'
    Invoke-Tool $rustup @('run', $russToolchain, 'rustc', '--version') 'Rust compiler check'
    Invoke-Tool $rustup @('run', $russToolchain, 'cargo', '--version') 'Cargo check'
    # Also pass the selected toolchain to a --run app's source watcher, without
    # changing the user's global rustup default.
    $env:RUSTUP_TOOLCHAIN = $russToolchain
    Write-Host '[3/3] Building RUSS. The first build downloads dependencies and can take several minutes...'
    $targetDirectory = Join-Path $root 'target'
    Invoke-Tool $cargo @(('+' + $russToolchain), 'build', '--locked', '--release', '--bin', 'russ',
        '--target', $russTarget, '--target-dir', $targetDirectory) 'RUSS build'
    $executable = Join-Path $targetDirectory ($russTarget + '\release\russ.exe')
    if (-not (Test-Path -LiteralPath $executable)) { throw 'Cargo finished but the RUSS executable was not found.' }
    Write-Host ''
    Write-Host ('Build complete: ' + $executable) -ForegroundColor Green
    if ($env:RUSS_BUILD_RUN -eq '1') {
        Start-Process -FilePath $executable -WorkingDirectory $root
    } else {
        Write-Host 'Double-click that russ.exe to start, or use build-windows.bat --run.'
    }
} catch {
    if ($script:russExitCode -eq 0) { $script:russExitCode = 1 }
    Write-Host ''
    Write-Host ('RUSS setup/build stopped: ' + $_.Exception.Message) -ForegroundColor Red
} finally {
    if ($script:russScratch) {
        Remove-Item -LiteralPath $script:russScratch -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit $script:russExitCode
