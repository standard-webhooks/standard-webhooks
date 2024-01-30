const { readFileSync, writeFileSync } = require('fs');
const { join } = require('path');
const semver = require('semver')

const versionFilePath = ".version";

const filesPaths = [
    versionFilePath,
    // Rust Client
    "rust/Cargo.toml",
    // CSharp
    "csharp/StandardWebhooks/StandardWebhooks.csproj",
    // Go
    // "go/internal/version/version.go",
    // Java
    "java/gradle.properties",
    "java/README.md",
    "java/lib/src/main/java/com/standardwebhooks/Webhook.java",
    // Javascript
    "javascript/package.json",
    "javascript/src/index.ts",
    // Python
    "python/standardwebhooks/__init__.py",
    // Ruby
    "ruby/Gemfile.lock",
    "ruby/standardwebhooks.gemspec",
    // Elixir
    "elixir/mix.exs"
];

const rootDir = join(__dirname, "..");

if (process.argv.length !== 3 || !semver.valid(process.argv[2])) {
    console.error("must supply a valid semantic version number");
    return;
}
const newVersion = process.argv[2];
const currentVersion = readFileSync(join(rootDir, versionFilePath), 'utf8').trim();

if (semver.lte(newVersion, currentVersion)) {
    console.error("supplied version must be greater than current version");
    return;
}

const replaceRegExp = new RegExp(currentVersion, 'g');

// Update Version Files
filesPaths.forEach((relativePath) => {
    const filePath = join(rootDir, relativePath);
    const content = readFileSync(filePath, 'utf8');
    const updated_content = content.replace(replaceRegExp, newVersion);
    writeFileSync(filePath, updated_content);
})

console.log("Version bumped from %s to %s, don't forget to update the changelog!", currentVersion, newVersion);
