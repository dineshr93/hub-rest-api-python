<#
.SYNOPSIS
    BlackDuck Rapid Scan for a single dependency across multiple package ecosystems.

.DESCRIPTION
    Creates a minimal project scaffold, then runs the BlackDuck detect script.
    Supported registries and coordinate formats:

      Registry    Platform              Coordinate format
      --------    --------              -----------------
      npm         JavaScript/Node.js    package/version  OR  @scope/package/version
      dart        Dart/Flutter          package/version
      pypi        Python                package/version
      maven       Java/JVM + Android    groupId:artifactId:version
      crates      Rust                  crate/version
      nuget       .NET/C#               package/version
      rubygems    Ruby                  gem/version
      go          Go                    module/path/vX.Y.Z
      packagist   PHP/Composer          vendor/package/version
      cocoapods   iOS/macOS             pod/version
      hex         Erlang/Elixir         package/version

.PARAMETER Registry
    Package ecosystem to scan (see table above).

.PARAMETER Coords
    Dependency coordinates in the registry's native format (see table above).

.PARAMETER ScanDir
    Optional working directory for generated project files.
    Defaults to a temp folder named bd-scan-<registry>-<package>-<version>.

.EXAMPLE
    .\scan-dependency.ps1 maven  "org.apache.commons:commons-lang3:3.12.0"
    .\scan-dependency.ps1 npm    "lodash/4.17.21"
    .\scan-dependency.ps1 npm    "@angular/core/17.0.0"
    .\scan-dependency.ps1 pypi   "requests/2.31.0"
    .\scan-dependency.ps1 nuget  "Newtonsoft.Json/13.0.3"
    .\scan-dependency.ps1 crates "serde/1.0.193"
    .\scan-dependency.ps1 go     "github.com/gin-gonic/gin/v1.9.1"
    .\scan-dependency.ps1 packagist "symfony/console/6.4.0"
    .\scan-dependency.ps1 rubygems  "rails/7.1.0"
    .\scan-dependency.ps1 cocoapods "Alamofire/5.9.0"
    .\scan-dependency.ps1 dart   "http/1.2.0"
    .\scan-dependency.ps1 hex    "phoenix/1.7.10"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('npm','dart','pypi','maven','crates','nuget','rubygems','go','packagist','cocoapods','hex')]
    [string]$Registry,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$Coords,

    [Parameter(Mandatory = $false, Position = 2)]
    [string]$ScanDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── helpers ───────────────────────────────────────────────────────────────────

function Write-Log  { param([string]$Msg) Write-Host "[INFO]  $Msg" }
function Write-Warn { param([string]$Msg) Write-Warning $Msg }
function Fail       { param([string]$Msg) Write-Error "[ERROR] $Msg"; exit 1 }

# Resolve an env var by name, checking process → user → machine scopes.
function Get-EnvVar {
    param([string]$Name)
    $val = [System.Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($val) { return $val }
    $val = [System.Environment]::GetEnvironmentVariable($Name, 'User')
    if ($val) { return $val }
    return [System.Environment]::GetEnvironmentVariable($Name, 'Machine')
}

# ── coordinate parsing ────────────────────────────────────────────────────────
#
# Returns a hashtable with at minimum: PackageName, Version
# maven    adds: GroupId, ArtifactId
# go       adds: Module  (full module path without version suffix)
# packagist adds: Vendor

function Parse-Coords {
    param([string]$Registry, [string]$Coords)

    switch ($Registry) {

        'maven' {
            $parts = $Coords -split ':'
            if ($parts.Count -ne 3) {
                Fail "maven coordinates must be  groupId:artifactId:version`n  Got: '$Coords'"
            }
            return @{
                GroupId     = $parts[0]
                ArtifactId  = $parts[1]
                Version     = $parts[2]
                PackageName = "$($parts[0]):$($parts[1])"
            }
        }

        'go' {
            # last path segment is the version (e.g. v1.9.1)
            $lastSlash = $Coords.LastIndexOf('/')
            if ($lastSlash -lt 1) {
                Fail "go coordinates must be  module/path/vX.Y.Z`n  Got: '$Coords'"
            }
            $module  = $Coords.Substring(0, $lastSlash)
            $ver     = $Coords.Substring($lastSlash + 1)
            if (-not $ver.StartsWith('v')) {
                Fail "go version must start with 'v'  Got: '$ver'"
            }
            return @{
                Module      = $module
                PackageName = $module
                Version     = $ver
            }
        }

        'packagist' {
            # vendor/package/version  (package itself may contain slashes for sub-namespaces)
            $parts = $Coords -split '/'
            if ($parts.Count -lt 3) {
                Fail "packagist coordinates must be  vendor/package/version`n  Got: '$Coords'"
            }
            $ver     = $parts[-1]
            $pkgName = ($parts[0..($parts.Count - 2)]) -join '/'
            return @{
                Vendor      = $parts[0]
                PackageName = $pkgName
                Version     = $ver
            }
        }

        'npm' {
            if ($Coords.StartsWith('@')) {
                # scoped package: @scope/name/version
                $parts = $Coords -split '/', 0  # unlimited splits
                if ($parts.Count -lt 3) {
                    Fail "npm scoped coordinates must be  @scope/package/version`n  Got: '$Coords'"
                }
                $ver     = $parts[-1]
                $pkgName = ($parts[0..($parts.Count - 2)]) -join '/'
                return @{ PackageName = $pkgName; Version = $ver }
            }
            else {
                $idx = $Coords.IndexOf('/')
                if ($idx -lt 1) {
                    Fail "npm coordinates must be  package/version`n  Got: '$Coords'"
                }
                return @{
                    PackageName = $Coords.Substring(0, $idx)
                    Version     = $Coords.Substring($idx + 1)
                }
            }
        }

        default {
            # dart, pypi, crates, nuget, rubygems, cocoapods, hex  →  package/version
            $idx = $Coords.IndexOf('/')
            if ($idx -lt 1) {
                Fail "$Registry coordinates must be  package/version`n  Got: '$Coords'"
            }
            return @{
                PackageName = $Coords.Substring(0, $idx)
                Version     = $Coords.Substring($idx + 1)
            }
        }
    }
}

# ── parse input ───────────────────────────────────────────────────────────────

$pkg        = Parse-Coords -Registry $Registry -Coords $Coords
$pkgName    = $pkg.PackageName
$version    = $pkg.Version
$safeName   = ($pkgName -replace '[^a-zA-Z0-9._-]', '_')

Write-Log "Registry    : $Registry"
Write-Log "Package     : $pkgName"
Write-Log "Version     : $version"

# ── environment variables ─────────────────────────────────────────────────────

$bdUrl   = Get-EnvVar 'BLACKDUCK_URL'
$bdToken = Get-EnvVar 'BLACKDUCK_API_TOKEN'

if (-not $bdUrl)   { Fail "BLACKDUCK_URL is not set. Export it or set it via System Properties." }
if (-not $bdToken) { Fail "BLACKDUCK_API_TOKEN is not set. Export it or set it via System Properties." }

# ── scan directory ────────────────────────────────────────────────────────────

if (-not $ScanDir) {
    $ScanDir = Join-Path $env:TEMP "bd-scan-$Registry-$safeName-$version"
}

New-Item -ItemType Directory -Force -Path $ScanDir | Out-Null
Write-Log "Scan dir    : $ScanDir"

# ── generate project files ────────────────────────────────────────────────────

Write-Log "Generating $Registry project files..."

switch ($Registry) {

    'maven' {
        $groupId    = $pkg.GroupId
        $artifactId = $pkg.ArtifactId

        @"
rootProject.name = '$artifactId-scan'
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'settings.gradle')

        @"
plugins {
    id 'java'
}

group   = '$groupId'
version = '$version'

repositories {
    mavenCentral()
    maven { url 'https://repo.spring.io/release' }
    maven { url 'https://plugins.gradle.org/m2/' }
}

dependencies {
    implementation '$groupId`:$artifactId`:$version'
}
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'build.gradle')

        # Gradle wrapper (required by detect)
        Push-Location $ScanDir
        try {
            $gradleCmd = Get-Command gradle -ErrorAction SilentlyContinue
            if (-not $gradleCmd) {
                Fail "gradle not found on PATH. Install Gradle 7+ (https://gradle.org/install/) and re-run."
            }
            Write-Log "Generating Gradle wrapper (Gradle 8.5)..."
            & gradle wrapper --gradle-version=8.5 --quiet
            if ($LASTEXITCODE -ne 0) { Fail "gradle wrapper failed (exit $LASTEXITCODE)." }
        }
        finally { Pop-Location }
    }

    'npm' {
        # Represent scoped packages correctly in the JSON key
        $depMap = @{ $pkgName = $version }
        @{
            name         = 'scan-project'
            version      = '1.0.0'
            private      = $true
            dependencies = $depMap
        } | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'package.json')

        # Generate package-lock.json (lockfileVersion 1) with a resolved URL.
        # lockfileVersion 1 is the most compatible format for BlackDuck's NPM
        # Package Lock detector and avoids the npm 7+ lockfileVersion 3 issue
        # (v3 has no legacy 'dependencies' block, causing fallback to Package Json
        # Parse at LOW accuracy and an accuracy-required failure).
        # The 'resolved' field is required for the detector to identify the
        # registry origin; without it the detector falls back to Package Json Parse.
        $tarballName = $pkgName.Split('/')[-1]   # strips scope: @angular/core → core
        $resolvedUrl = "https://registry.npmjs.org/$pkgName/-/$tarballName-$version.tgz"
        [ordered]@{
            name            = 'scan-project'
            version         = '1.0.0'
            lockfileVersion = 1
            requires        = $true
            dependencies    = [ordered]@{
                $pkgName = [ordered]@{
                    version  = $version
                    resolved = $resolvedUrl
                }
            }
        } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'package-lock.json')
    }

    'dart' {
        @"
name: scan_project
description: BlackDuck scan project
version: 1.0.0

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  ${pkgName}: ^$version
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'pubspec.yaml')

        # Generate pubspec.lock so the Dart PubSpec Lock detector runs (HIGH accuracy).
        # pubspec.yaml alone triggers Dart PubSpec detector which may not achieve required accuracy.
        @"
# Generated by pub
# See https://dart.dev/tools/pub/glossary#lockfile
packages:
  $pkgName`:
    dependency: "direct main"
    description:
      name: $pkgName
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
      url: "https://pub.dev"
    source: hosted
    version: "$version"
sdks:
  dart: ">=3.0.0 <4.0.0"
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'pubspec.lock')
    }

    'pypi' {
        # Generate Pipfile + Pipfile.lock for the Pipenv Lock detector.
        # Requirements.txt alone triggers PIP Requirements Parse (LOW accuracy).
        # Pipfile.lock triggers Pipenv Lock detector (HIGH accuracy).
        @"
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
$pkgName = "==$version"

[dev-packages]

[requires]
python_version = "3.11"
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Pipfile')

        # Pipfile.lock in JSON format
        [ordered]@{
            '_meta' = [ordered]@{
                hash = [ordered]@{
                    sha256 = '0000000000000000000000000000000000000000000000000000000000000000'
                }
                'pipfile-spec' = 6
                requires = [ordered]@{
                    python_version = '3.11'
                }
                sources = @(
                    [ordered]@{
                        name = 'pypi'
                        url = 'https://pypi.org/simple'
                        verify_ssl = $true
                    }
                )
            }
            default = [ordered]@{
                $pkgName = [ordered]@{
                    index = 'pypi'
                    version = "==$version"
                }
            }
            develop = [ordered]@{}
        } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Pipfile.lock')
    }

    'crates' {
        @"
[package]
name    = "scan-project"
version = "0.1.0"
edition = "2021"

[dependencies]
$pkgName = "$version"
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Cargo.toml')

        # Generate Cargo.lock so the Cargo Lock detector runs (HIGH accuracy).
        # Cargo.toml alone triggers Cargo Toml detector which may not achieve required accuracy.
        @"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "scan-project"
version = "0.1.0"
dependencies = [
 "$pkgName",
]

[[package]]
name = "$pkgName"
version = "$version"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Cargo.lock')
    }

    'nuget' {
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>ScanProject</AssemblyName>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="$pkgName" Version="$version" />
  </ItemGroup>
</Project>
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'ScanProject.csproj')
    }

    'rubygems' {
        @"
source 'https://rubygems.org'

gem '$pkgName', '$version'
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Gemfile')
    }

    'go' {
        $module = $pkg.Module
        @"
module scan-project

go 1.21

require $module $version
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'go.mod')

        # go.sum must exist (can be empty for STATELESS scan)
        '' | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'go.sum')
    }

    'packagist' {
        @{
            name        = 'scan/project'
            description = 'BlackDuck scan project'
            require     = @{ $pkgName = $version }
        } | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'composer.json')
    }

    'cocoapods' {
        @"
platform :ios, '14.0'
use_frameworks!

target 'ScanProject' do
  pod '$pkgName', '~> $version'
end
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'Podfile')
    }

    'hex' {
        # Elixir atom names use underscores; replace hyphens
        $atomName = $pkgName -replace '-', '_'
        @"
defmodule ScanProject.MixProject do
  use Mix.Project

  def project do
    [
      app:     :scan_project,
      version: "0.1.0",
      elixir:  "~> 1.14",
      deps:    deps()
    ]
  end

  defp deps do
    [
      {:$atomName, "~> $version"}
    ]
  end
end
"@ | Set-Content -Encoding UTF8 (Join-Path $ScanDir 'mix.exs')
    }
}

# ── BlackDuck detect arguments ────────────────────────────────────────────────

$pjName   = "$safeName-scan"
$snapshot = $version

Write-Log "BlackDuck URL     : $bdUrl"
Write-Log "Project name      : $pjName"
Write-Log "Project version   : $snapshot"

# Detector type and any registry-specific flags
$registryArgs = switch ($Registry) {
    'maven' {
        @(
            "--detect.gradle.build.command=clean"
            "--detect.gradle.included.configurations=runtimeClasspath"
            "--detect.gradle.path=gradlew.bat"
            "--detect.included.detector.types=GRADLE"
            "--detect.accuracy.required=GRADLE"
        )
    }
    'npm'       { @( "--detect.included.detector.types=NPM"      ; "--detect.npm.include.dev.dependencies=false" ) }
    'dart'      { @( "--detect.included.detector.types=DART"     ) }
    'pypi'      { @( "--detect.included.detector.types=PIP"      ) }
    'crates'    { @( "--detect.included.detector.types=CARGO"    ) }
    'nuget'     { @( "--detect.included.detector.types=NUGET"    ) }
    'rubygems'  { @( "--detect.included.detector.types=RUBYGEMS" ) }
    'go'        { @( "--detect.included.detector.types=GO_MOD"   ) }
    'packagist' { @( "--detect.included.detector.types=PACKAGIST" ) }
    'cocoapods' { @( "--detect.included.detector.types=COCOAPODS") }
    'hex'       { @( "--detect.included.detector.types=HEX"      ) }
}

$detectArgs = (@(
    "--blackduck.trust.cert=true"
    "--blackduck.url=$bdUrl"
    "--blackduck.api.token=$bdToken"
    "--detect.blackduck.scan.mode=STATELESS"
    "--detect.excluded.directories.defaults.disabled=false"
    "--detect.detector.search.depth=50"
    "--detect.cleanup=false"
    "--logging.level.detect=DEBUG"
    "--detect.tools=DETECTOR"
    "--detect.source.path=."
    "--detect.timeout=300"
) + $registryArgs) -join ' '

$detectCmd = "bash <(curl -s https://detect.blackduck.com/detect10.sh) $detectArgs"

# ── locate bash (Git Bash → WSL) ──────────────────────────────────────────────

Write-Log "Starting BlackDuck Rapid Scan..."

$gitBashPaths = @(
    'C:\Program Files\Git\bin\bash.exe'
    'C:\Program Files (x86)\Git\bin\bash.exe'
)

$bashExe = $null
foreach ($p in $gitBashPaths) {
    if (Test-Path $p) { $bashExe = $p; break }
}

$scanExit = 0

if (-not $bashExe) {
    $wslExe = Get-Command wsl -ErrorAction SilentlyContinue
    if ($wslExe) {
        Write-Log "Using WSL bash..."
        $wslPath = (wsl wslpath -u ($ScanDir -replace '\\', '/') 2>$null).Trim()
        Push-Location $ScanDir
        try {
            wsl bash -c "cd '$wslPath' && $detectCmd"
            $scanExit = $LASTEXITCODE
        }
        finally { Pop-Location }
    }
    else {
        Fail "Neither Git Bash nor WSL found. Install Git for Windows (https://git-scm.com) or enable WSL."
    }
}
else {
    Write-Log "Using Git Bash: $bashExe"
    Push-Location $ScanDir
    try {
        $unixPath = (& $bashExe -c "cygpath -u '$(($ScanDir -replace '\\', '/'))'" 2>&1) |
                    Where-Object { $_ -notmatch '^$' } | Select-Object -First 1
        if (-not $unixPath) {
            $unixPath = ($ScanDir -replace '\\', '/') -replace '^([A-Za-z]):', '/$1'
        }
        & $bashExe -c "cd '$unixPath' && $detectCmd"
        $scanExit = $LASTEXITCODE
    }
    finally { Pop-Location }
}

# ── results ───────────────────────────────────────────────────────────────────

if ($scanExit -eq 0) {
    Write-Log "Scan complete. View results in BlackDuck:"
    Write-Log "  Project : $pjName"
    Write-Log "  Version : $snapshot"
    Write-Log "  URL     : $bdUrl/api/projects?q=$pjName"
}
# else {
#     Fail "BlackDuck detect exited with code $scanExit. Check logs above for details."
# }
