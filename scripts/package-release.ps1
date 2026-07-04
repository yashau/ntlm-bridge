$ErrorActionPreference = "Stop"

$version = & "$PSScriptRoot/calver.ps1" validate
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$dist = Join-Path $root "dist"
$stage = Join-Path $dist "ntlm-bridge-$version-windows-x64"
$exe = Join-Path $root "target/release/ntlm-bridge.exe"
$zip = "$stage.zip"

if (-not (Test-Path $exe)) {
    throw "release binary not found: $exe"
}

Remove-Item -Recurse -Force -LiteralPath $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item -LiteralPath $exe -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "config.example.toml") -Destination $stage
if (Test-Path (Join-Path $root "LICENSE")) {
    Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $stage
}

Remove-Item -Force -LiteralPath $zip -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Write-Output $zip
