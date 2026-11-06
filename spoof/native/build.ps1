param(
    [string]$Ndk = $env:ANDROID_NDK_HOME
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not $Ndk) {
    $sdkNdk = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
    if (Test-Path $sdkNdk) {
        $Ndk = Get-ChildItem $sdkNdk -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $Ndk) {
    throw "Set ANDROID_NDK_HOME or pass -Ndk <path>."
}

$clangxx = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android36-clang++.cmd"
if (-not (Test-Path $clangxx)) {
    throw "NDK clang++ not found: $clangxx"
}

$arguments = @(
    "-shared", "-fPIC", "-O2", "-std=c++17",
    "-fno-exceptions", "-fno-rtti", "-fvisibility=hidden",
    "-static-libstdc++",
    "-pthread",
    "-Wl,-soname,libspoof.so", "-Wl,--exclude-libs,ALL",
    "-o", "..\libspoof.so",
    "libspoof.cpp",
    "-llog"
)
& $clangxx @arguments

if ($LASTEXITCODE -ne 0) {
    throw "clang++ failed with exit code $LASTEXITCODE"
}
Write-Host "built $(Resolve-Path ..\libspoof.so)"
