#!/usr/bin/env bash
# ============================================================
# BlackDuck Rapid Scan for a single dependency across
# multiple package ecosystems.
#
# Usage: ./scan-dependency.sh <registry> <coordinates> [scan_dir]
#
# Registry    Platform              Coordinate format
# --------    --------              -----------------
# npm         JavaScript/Node.js    package/version  OR  @scope/package/version
# dart        Dart/Flutter          package/version
# pypi        Python                package/version
# maven       Java/JVM + Android    groupId:artifactId:version
# crates      Rust                  crate/version
# nuget       .NET/C#               package/version
# rubygems    Ruby                  gem/version
# go          Go                    module/path/vX.Y.Z
# packagist   PHP/Composer          vendor/package/version
# cocoapods   iOS/macOS             pod/version
# hex         Erlang/Elixir         package/version
#
# Required environment variables:
#   BLACKDUCK_URL        e.g. https://your-blackduck-server
#   BLACKDUCK_API_TOKEN  BlackDuck API token
#
# Examples:
#   ./scan-dependency.sh maven     "org.apache.commons:commons-lang3:3.12.0"
#   ./scan-dependency.sh npm       "lodash/4.17.21"
#   ./scan-dependency.sh npm       "@angular/core/17.0.0"
#   ./scan-dependency.sh pypi      "requests/2.31.0"
#   ./scan-dependency.sh nuget     "Newtonsoft.Json/13.0.3"
#   ./scan-dependency.sh crates    "serde/1.0.193"
#   ./scan-dependency.sh go        "github.com/gin-gonic/gin/v1.9.1"
#   ./scan-dependency.sh packagist "symfony/console/6.4.0"
#   ./scan-dependency.sh rubygems  "rails/7.1.0"
#   ./scan-dependency.sh cocoapods "Alamofire/5.9.0"
#   ./scan-dependency.sh dart      "http/1.2.0"
#   ./scan-dependency.sh hex       "phoenix/1.7.10"
# ============================================================
set -euo pipefail

# ── helpers ──────────────────────────────────────────────────

VALID_REGISTRIES="npm dart pypi maven crates nuget rubygems go packagist cocoapods hex"

usage() {
    echo ""
    echo "Usage: $0 <registry> <coordinates> [scan_dir]"
    echo ""
    echo "  registry      One of: $VALID_REGISTRIES"
    echo "  coordinates   See header comment for format per registry"
    echo "  scan_dir      Optional working directory (default: temp dir)"
    echo ""
    echo "Required environment variables:"
    echo "  BLACKDUCK_URL        e.g. https://your-blackduck-server"
    echo "  BLACKDUCK_API_TOKEN  BlackDuck API token"
    exit 1
}

log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

# Resolve an env var, falling back to Windows CMD when running under Git Bash.
get_env() {
    local var_name="$1"
    local val="${!var_name:-}"
    if [ -z "$val" ] && command -v cmd.exe &>/dev/null; then
        local win_val
        win_val=$(cmd.exe /c "echo %${var_name}%" 2>/dev/null | tr -d '\r\n')
        if [[ "$win_val" != "%${var_name}%" ]]; then
            val="$win_val"
        fi
    fi
    echo "$val"
}

# Sanitise a string for use in file/directory names.
safe_name() { echo "$1" | tr -cs 'a-zA-Z0-9._-' '_'; }

# ── argument validation ───────────────────────────────────────

[ $# -lt 2 ] && usage

REGISTRY="$1"
COORDS="$2"
SCAN_DIR="${3:-}"

# Validate registry
valid=0
for r in $VALID_REGISTRIES; do
    [ "$r" = "$REGISTRY" ] && valid=1 && break
done
if [ $valid -eq 0 ]; then
    err "Unknown registry '$REGISTRY'. Valid: $VALID_REGISTRIES"
fi

# ── coordinate parsing ────────────────────────────────────────
#
# Sets globals: PKG_NAME, VERSION
# maven    also sets: GROUP_ID, ARTIFACT_ID
# go       also sets: MODULE
# packagist also sets: VENDOR

parse_coords() {
    case "$REGISTRY" in

        maven)
            IFS=':' read -ra PARTS <<< "$COORDS"
            if [ ${#PARTS[@]} -ne 3 ]; then
                err "maven coordinates must be  groupId:artifactId:version  Got: '$COORDS'"
            fi
            GROUP_ID="${PARTS[0]}"
            ARTIFACT_ID="${PARTS[1]}"
            VERSION="${PARTS[2]}"
            PKG_NAME="$GROUP_ID:$ARTIFACT_ID"
            ;;

        go)
            # last path segment is the version (vX.Y.Z)
            VERSION="${COORDS##*/}"
            MODULE="${COORDS%/*}"
            if [[ "$VERSION" != v* ]]; then
                err "go version must start with 'v'  Got: '$VERSION'"
            fi
            if [ -z "$MODULE" ]; then
                err "go coordinates must be  module/path/vX.Y.Z  Got: '$COORDS'"
            fi
            PKG_NAME="$MODULE"
            ;;

        packagist)
            # vendor/package/version
            IFS='/' read -ra PARTS <<< "$COORDS"
            if [ ${#PARTS[@]} -lt 3 ]; then
                err "packagist coordinates must be  vendor/package/version  Got: '$COORDS'"
            fi
            VERSION="${PARTS[-1]}"
            VENDOR="${PARTS[0]}"
            # drop last element (version) to get package name
            PKG_NAME="$(IFS='/'; echo "${PARTS[*]::${#PARTS[@]}-1}")"
            ;;

        npm)
            if [[ "$COORDS" == @* ]]; then
                # @scope/name/version
                IFS='/' read -ra PARTS <<< "$COORDS"
                if [ ${#PARTS[@]} -lt 3 ]; then
                    err "npm scoped coordinates must be  @scope/package/version  Got: '$COORDS'"
                fi
                VERSION="${PARTS[-1]}"
                PKG_NAME="$(IFS='/'; echo "${PARTS[*]::${#PARTS[@]}-1}")"
            else
                PKG_NAME="${COORDS%%/*}"
                VERSION="${COORDS#*/}"
                if [ "$PKG_NAME" = "$COORDS" ]; then
                    err "npm coordinates must be  package/version  Got: '$COORDS'"
                fi
            fi
            ;;

        *)
            # dart, pypi, crates, nuget, rubygems, cocoapods, hex  →  package/version
            PKG_NAME="${COORDS%%/*}"
            VERSION="${COORDS#*/}"
            if [ "$PKG_NAME" = "$COORDS" ]; then
                err "$REGISTRY coordinates must be  package/version  Got: '$COORDS'"
            fi
            ;;
    esac
}

parse_coords

log "Registry    : $REGISTRY"
log "Package     : $PKG_NAME"
log "Version     : $VERSION"

SAFE_NAME="$(safe_name "$PKG_NAME")"

# ── environment variables ─────────────────────────────────────

BD_URL=$(get_env "BLACKDUCK_URL")
BD_TOKEN=$(get_env "BLACKDUCK_API_TOKEN")

if [ -z "$BD_URL" ]; then
    err "BLACKDUCK_URL is not set."
fi
if [ -z "$BD_TOKEN" ]; then
    err "BLACKDUCK_API_TOKEN is not set."
fi

# ── scan directory ────────────────────────────────────────────

if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR="$(mktemp -d)/bd-scan-${REGISTRY}-${SAFE_NAME}-${VERSION}"
fi

mkdir -p "$SCAN_DIR"
log "Scan dir    : $SCAN_DIR"

# ── generate project files ────────────────────────────────────

log "Generating $REGISTRY project files..."

case "$REGISTRY" in

    maven)
        cat > "$SCAN_DIR/settings.gradle" <<EOF
rootProject.name = '${ARTIFACT_ID}-scan'
EOF

        cat > "$SCAN_DIR/build.gradle" <<EOF
plugins {
    id 'java'
}

group   = '${GROUP_ID}'
version = '${VERSION}'

repositories {
    mavenCentral()
    maven { url 'https://repo.spring.io/release' }
    maven { url 'https://plugins.gradle.org/m2/' }
}

dependencies {
    implementation '${GROUP_ID}:${ARTIFACT_ID}:${VERSION}'
}
EOF

        # Gradle wrapper
        pushd "$SCAN_DIR" > /dev/null
        if command -v gradle &>/dev/null; then
            log "Generating Gradle wrapper (Gradle 8.5)..."
            gradle wrapper --gradle-version=8.5 --quiet
        elif command -v gradle.bat &>/dev/null; then
            gradle.bat wrapper --gradle-version=8.5 --quiet
        else
            err "gradle not found on PATH. Install Gradle 7+ (https://gradle.org/install/)."
        fi
        popd > /dev/null
        ;;

    npm)
        cat > "$SCAN_DIR/package.json" <<EOF
{
  "name": "scan-project",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "${PKG_NAME}": "${VERSION}"
  }
}
EOF
        # Generate package-lock.json (lockfileVersion 1) with a resolved URL.
        # lockfileVersion 1 is the most compatible format for BlackDuck's NPM
        # Package Lock detector and avoids the npm 7+ lockfileVersion 3 issue
        # (v3 has no legacy 'dependencies' block, causing fallback to Package Json
        # Parse at LOW accuracy and an accuracy-required failure).
        # The 'resolved' field is required for the detector to identify the
        # registry origin; without it the detector falls back to Package Json Parse.
        TARBALL_NAME="${PKG_NAME##*/}"   # strips scope: @angular/core → core
        RESOLVED_URL="https://registry.npmjs.org/${PKG_NAME}/-/${TARBALL_NAME}-${VERSION}.tgz"
        log "Tarball name: $TARBALL_NAME"
        log "Resolved URL: $RESOLVED_URL"
        cat > "$SCAN_DIR/package-lock.json" <<EOF
{
  "name": "scan-project",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "${PKG_NAME}": {
      "version": "${VERSION}",
      "resolved": "${RESOLVED_URL}"
    }
  }
}
EOF
        ;;

    dart)
        cat > "$SCAN_DIR/pubspec.yaml" <<EOF
name: scan_project
description: BlackDuck scan project
version: 1.0.0

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  ${PKG_NAME}: ^${VERSION}
EOF

        # Generate pubspec.lock so the Dart PubSpec Lock detector runs (HIGH accuracy).
        # pubspec.yaml alone triggers Dart PubSpec detector which may not achieve required accuracy.
        cat > "$SCAN_DIR/pubspec.lock" <<EOF
# Generated by pub
# See https://dart.dev/tools/pub/glossary#lockfile
packages:
  ${PKG_NAME}:
    dependency: "direct main"
    description:
      name: ${PKG_NAME}
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
      url: "https://pub.dev"
    source: hosted
    version: "${VERSION}"
sdks:
  dart: ">=3.0.0 <4.0.0"
EOF
        ;;

    pypi)
        # Generate Pipfile + Pipfile.lock for the Pipenv Lock detector.
        # Requirements.txt alone triggers PIP Requirements Parse (LOW accuracy).
        # Pipfile.lock triggers Pipenv Lock detector (HIGH accuracy).
        cat > "$SCAN_DIR/Pipfile" <<EOF
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
${PKG_NAME} = "==${VERSION}"

[dev-packages]

[requires]
python_version = "3.11"
EOF

        # Pipfile.lock in JSON format
        cat > "$SCAN_DIR/Pipfile.lock" <<EOF
{
    "_meta": {
        "hash": {
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.11"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "${PKG_NAME}": {
            "index": "pypi",
            "version": "==${VERSION}"
        }
    },
    "develop": {}
}
EOF
        ;;

    crates)
        cat > "$SCAN_DIR/Cargo.toml" <<EOF
[package]
name    = "scan-project"
version = "0.1.0"
edition = "2021"

[dependencies]
${PKG_NAME} = "${VERSION}"
EOF

        # Generate Cargo.lock so the Cargo Lock detector runs (HIGH accuracy).
        # Cargo.toml alone triggers Cargo Toml detector which may not achieve required accuracy.
        cat > "$SCAN_DIR/Cargo.lock" <<EOF
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "scan-project"
version = "0.1.0"
dependencies = [
 "${PKG_NAME}",
]

[[package]]
name = "${PKG_NAME}"
version = "${VERSION}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
EOF
        ;;

    nuget)
        cat > "$SCAN_DIR/ScanProject.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>ScanProject</AssemblyName>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="${PKG_NAME}" Version="${VERSION}" />
  </ItemGroup>
</Project>
EOF
        ;;

    rubygems)
        cat > "$SCAN_DIR/Gemfile" <<EOF
source 'https://rubygems.org'

gem '${PKG_NAME}', '${VERSION}'
EOF
        ;;

    go)
        cat > "$SCAN_DIR/go.mod" <<EOF
module scan-project

go 1.21

require ${MODULE} ${VERSION}
EOF
        # go.sum must exist (can be empty for STATELESS scan)
        touch "$SCAN_DIR/go.sum"
        ;;

    packagist)
        cat > "$SCAN_DIR/composer.json" <<EOF
{
  "name": "scan/project",
  "description": "BlackDuck scan project",
  "require": {
    "${PKG_NAME}": "${VERSION}"
  }
}
EOF
        ;;

    cocoapods)
        cat > "$SCAN_DIR/Podfile" <<EOF
platform :ios, '14.0'
use_frameworks!

target 'ScanProject' do
  pod '${PKG_NAME}', '~> ${VERSION}'
end
EOF
        ;;

    hex)
        # Elixir atom names use underscores
        ATOM_NAME="${PKG_NAME//-/_}"
        cat > "$SCAN_DIR/mix.exs" <<EOF
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
      {:${ATOM_NAME}, "~> ${VERSION}"}
    ]
  end
end
EOF
        ;;
esac

# ── BlackDuck detect arguments ────────────────────────────────

PJ_NAME="${SAFE_NAME}-scan"
SNAPSHOT="${VERSION}"

log "BlackDuck URL     : ${BD_URL}"
log "Project name      : ${PJ_NAME}"
log "Project version   : ${SNAPSHOT}"

# Registry-specific detect flags
case "$REGISTRY" in
    maven)
        REGISTRY_ARGS=(
            "--detect.gradle.build.command=clean"
            "--detect.gradle.included.configurations=runtimeClasspath"
            "--detect.gradle.path=gradlew"
            "--detect.included.detector.types=GRADLE"
            "--detect.accuracy.required=GRADLE"
        )
        ;;
    npm)
        REGISTRY_ARGS=(
            "--detect.included.detector.types=NPM"
            "--detect.npm.include.dev.dependencies=false"
        )
        ;;
    dart)      REGISTRY_ARGS=( "--detect.included.detector.types=DART"     ) ;;
    pypi)      REGISTRY_ARGS=( "--detect.included.detector.types=PIP"      ) ;;
    crates)    REGISTRY_ARGS=( "--detect.included.detector.types=CARGO"    ) ;;
    nuget)     REGISTRY_ARGS=( "--detect.included.detector.types=NUGET"    ) ;;
    rubygems)  REGISTRY_ARGS=( "--detect.included.detector.types=RUBYGEMS" ) ;;
    go)        REGISTRY_ARGS=( "--detect.included.detector.types=GO_MOD"   ) ;;
    packagist) REGISTRY_ARGS=( "--detect.included.detector.types=PACKAGIST" ) ;;
    cocoapods) REGISTRY_ARGS=( "--detect.included.detector.types=COCOAPODS") ;;
    hex)       REGISTRY_ARGS=( "--detect.included.detector.types=HEX"      ) ;;
esac

DETECT_ARGS=(
    "--blackduck.trust.cert=true"
    "--blackduck.url=${BD_URL}"
    "--blackduck.api.token=${BD_TOKEN}"
    "--detect.blackduck.scan.mode=STATELESS"
    "--detect.excluded.directories.defaults.disabled=false"
    "--detect.detector.search.depth=50"
    "--detect.cleanup=false"
    "--logging.level.detect=DEBUG"
    "--detect.tools=DETECTOR"
    "--detect.source.path=."
    "--detect.timeout=300"
    "${REGISTRY_ARGS[@]}"
)

# ── run BlackDuck scan ────────────────────────────────────────

log "Starting BlackDuck Rapid Scan..."

pushd "$SCAN_DIR" > /dev/null
bash <(curl -s https://detect.blackduck.com/detect10.sh) "${DETECT_ARGS[@]}"
SCAN_EXIT=$?
popd > /dev/null

if [ $SCAN_EXIT -eq 0 ]; then
    log "Scan complete. View results in BlackDuck:"
    log "  Project : ${PJ_NAME}"
    log "  Version : ${SNAPSHOT}"
    log "  URL     : ${BD_URL}/api/projects?q=${PJ_NAME}"
else
    echo ""
    echo "============================================================"
    echo "[ERROR] BlackDuck detect exited with code ${SCAN_EXIT}"
    echo "============================================================"
    echo ""
    echo "Scan directory: $SCAN_DIR"
    echo ""
    echo "Generated files:"
    ls -la "$SCAN_DIR" 2>/dev/null || true
    echo ""
    if [ "$REGISTRY" = "npm" ]; then
        echo "--- package.json ---"
        cat "$SCAN_DIR/package.json" 2>/dev/null || echo "(not found)"
        echo ""
        echo "--- package-lock.json ---"
        cat "$SCAN_DIR/package-lock.json" 2>/dev/null || echo "(not found)"
        echo ""
    fi
    echo "Common exit codes:"
    echo "  3 = Policy violations found"
    echo "  1 = Detector/accuracy failure"
    echo ""
    echo "Check the detect logs above for detailed error messages."
    echo "Look for lines containing 'Accuracy Not Met' or 'Detector Issue'."
    exit $SCAN_EXIT
fi
