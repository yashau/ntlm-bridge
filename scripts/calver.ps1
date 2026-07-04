param(
    [ValidateSet("show", "next", "cut", "validate")]
    [string]$Command = "next",

    [string]$Date = (Get-Date -Format "yyyy-MM-dd"),

    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Test-CalVerTag {
    param([string]$Tag)

    if ($Tag -notmatch '^(?<date>\d{4}-\d{2}-\d{2})-(?<n>[1-9]\d*)$') {
        return $false
    }

    try {
        [datetime]::ParseExact($Matches.date, "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture) | Out-Null
    } catch {
        return $false
    }

    return $true
}

function Get-ReleaseTagForHead {
    $tags = git tag --points-at HEAD --list "????-??-??-*"
    foreach ($tag in $tags) {
        if (Test-CalVerTag $tag) {
            return $tag
        }
    }
    return $null
}

function Get-CurrentReleaseTag {
    if ($env:GITHUB_REF_TYPE -eq "tag" -and $env:GITHUB_REF_NAME) {
        return $env:GITHUB_REF_NAME
    }

    if ($env:GITHUB_REF -match '^refs/tags/(.+)$') {
        return $Matches[1]
    }

    return Get-ReleaseTagForHead
}

function Get-NextTag {
    param([string]$Date)

    try {
        [datetime]::ParseExact($Date, "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture) | Out-Null
    } catch {
        throw "invalid release date '$Date'; expected YYYY-MM-DD"
    }

    $max = 0
    $tags = git tag --list "$Date-*"
    $escapedDate = [regex]::Escape($Date)
    foreach ($tag in $tags) {
        if ($tag -match "^$escapedDate-(?<n>[1-9]\d*)$") {
            $n = [int]$Matches.n
            if ($n -gt $max) {
                $max = $n
            }
        }
    }

    return "$Date-$($max + 1)"
}

switch ($Command) {
    "show" {
        $tag = Get-ReleaseTagForHead
        if (-not $tag) {
            throw "HEAD does not have a YYYY-MM-DD-N release tag"
        }
        Write-Output $tag
    }

    "next" {
        Write-Output (Get-NextTag $Date)
    }

    "cut" {
        git rev-parse --verify HEAD *> $null
        if (-not $Force -and (git status --porcelain)) {
            throw "working tree is not clean; commit or stash changes before cutting a release tag"
        }

        $tag = Get-NextTag $Date
        if (git rev-parse -q --verify "refs/tags/$tag") {
            throw "tag already exists: $tag"
        }

        git tag -a $tag -m "Release $tag"
        Write-Output $tag
    }

    "validate" {
        $tag = Get-CurrentReleaseTag
        if (-not $tag) {
            throw "no release tag found in CI environment or on HEAD"
        }
        if (-not (Test-CalVerTag $tag)) {
            throw "invalid release tag '$tag'; expected YYYY-MM-DD-N"
        }
        Write-Output $tag
    }
}
