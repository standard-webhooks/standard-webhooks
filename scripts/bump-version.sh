#!/usr/bin/env bash
# Set every library to the same version.
#
#   scripts/bump-version.sh 1.2.0
#
# Go and PHP have no version in their manifests: they're versioned by the git
# tag (the Go release workflow pushes the matching "libraries/vX.Y.Z" tag).
# After merging the bump, release everything with:
#
#   git tag vX.Y.Z && git push origin vX.Y.Z

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <version>   (e.g. $0 1.2.0)" >&2
    exit 1
fi

VERSION="${1#v}"
# Plain X.Y.Z only: prerelease suffixes are spelled differently per ecosystem
# (RubyGems "1.0.0.pre.rc.1", PEP 440 "1.0.0rc1", ...), so they can't be synced
# with one string.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: '$VERSION' is not a plain X.Y.Z version" >&2
    exit 1
fi
export VERSION

cd "$(dirname "$0")/../libraries"

# bump FILE PERL_REGEX
# The regex must capture the text before the version as $1 and after it as $2.
# Fails if the pattern doesn't match, so a moved/renamed field isn't silently
# skipped.
bump() {
    local file="$1" regex="$2"
    if [ ! -f "$file" ]; then
        echo "error: $file not found" >&2
        exit 1
    fi
    if ! perl -0ne "exit(!(m{$regex}m))" "$file"; then
        echo "error: version pattern not found in $file" >&2
        exit 1
    fi
    perl -0pi -e "s{$regex}{\${1}\$ENV{VERSION}\${2}}m" "$file"
    echo "  $file"
}

echo "Setting version to $VERSION:"

bump csharp/StandardWebhooks/StandardWebhooks.csproj '(<Version>)[^<]+(</Version>)'
bump elixir/mix.exs '(^\s*version: ")[^"]+(",)'
bump java/pom.xml '(<artifactId>standardwebhooks</artifactId>\s*<version>)[^<]+(</version>)'
bump javascript/package.json '(^  "version": ")[^"]+(",)'
# The root package entry appears twice in the lockfile (top level + packages."").
bump javascript/package-lock.json '(^  "version": ")[^"]+(",)'
bump javascript/package-lock.json '(^    "": \{\n      "name": "standardwebhooks",\n      "version": ")[^"]+(",)'
bump python/standardwebhooks/__init__.py '(^__version__ = ")[^"]+(")'
bump ruby/standardwebhooks.gemspec '(spec\.version = ")[^"]+(")'
bump ruby/Gemfile.lock '(^    standardwebhooks \()[^)]+(\))'
bump rust/Cargo.toml '(^\[package\][^\[]*?^version = ")[^"]+(")'
# Cargo.lock isn't committed for the library, but keep a local one in sync.
if [ -f rust/Cargo.lock ]; then
    bump rust/Cargo.lock '(^name = "standardwebhooks"\nversion = ")[^"]+(")'
fi

echo "Done. Review with: git diff"
