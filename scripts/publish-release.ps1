$ErrorActionPreference = "Stop"

$version = & "$PSScriptRoot/calver.ps1" validate
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$files = @(Get-ChildItem -Path (Join-Path $root "dist") -Filter "ntlm-bridge-$version-*.zip")

if ($files.Count -eq 0) {
    throw "no release artifacts found for $version in dist/"
}

$paths = @($files | ForEach-Object { $_.FullName })

gh release view $version *> $null
if ($LASTEXITCODE -eq 0) {
    gh release upload $version @paths --clobber
} else {
    gh release create $version @paths --title "ntlm-bridge $version" --notes "Release $version"
}
