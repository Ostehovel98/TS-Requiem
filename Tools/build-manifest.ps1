param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$PrivateKeyPemPath,
  [Parameter(Mandatory=$true)][string]$PublicKeyPemPath
)

$ErrorActionPreference = "Stop"

function Write-Utf8NoBom([string]$path, [string]$text) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

# Paths
$valuesPath = Join-Path $RepoRoot "Requiem\manifest.values.json"
$outJson    = Join-Path $RepoRoot "Requiem\manifest.json"
$outSig     = Join-Path $RepoRoot "Requiem\manifest.sig"

if (!(Test-Path $valuesPath)) { throw "Missing: $valuesPath" }
if (!(Test-Path $PrivateKeyPemPath)) { throw "Missing: $PrivateKeyPemPath" }
if (!(Test-Path $PublicKeyPemPath)) { throw "Missing: $PublicKeyPemPath" }

# Load values
$values = Get-Content -Raw -Encoding UTF8 $valuesPath | ConvertFrom-Json
$publishedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Canonical ordered object
$manifest = [ordered]@{
  product        = [string]$values.product
  minVersion     = [string]$values.minVersion
  currentVersion = [string]$values.currentVersion
  releaseKeyId   = [string]$values.releaseKeyId
  message        = [string]$values.message
  publishedUtc   = $publishedUtc
}

# Canonical JSON: minified, UTF-8 no BOM, ends with LF
# ConvertTo-Json adds whitespace, so we minify deterministically by round-tripping
$jsonPretty = ($manifest | ConvertTo-Json -Depth 5)
$objRoundTrip = $jsonPretty | ConvertFrom-Json
$jsonMin = ($objRoundTrip | ConvertTo-Json -Depth 5 -Compress) + "`n"

Write-Utf8NoBom $outJson $jsonMin

# Load keys (PEM) and sign
$privPem = Get-Content -Raw -Encoding UTF8 $PrivateKeyPemPath
$pubPem  = Get-Content -Raw -Encoding UTF8 $PublicKeyPemPath

$ecdsaPriv = [System.Security.Cryptography.ECDsa]::Create()
$ecdsaPriv.ImportFromPem($privPem)

$ecdsaPub = [System.Security.Cryptography.ECDsa]::Create()
$ecdsaPub.ImportFromPem($pubPem)

$dataBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonMin)

# DER signature (same type your mod expects)
$sigBytes = $ecdsaPriv.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$sigB64 = [Convert]::ToBase64String($sigBytes) + "`n"
Write-Utf8NoBom $outSig $sigB64

# Verify immediately (idiot-proof guardrail)
$ok = $ecdsaPub.VerifyData($dataBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
if (-not $ok) { throw "Signature verification FAILED right after signing (should never happen)." }

Write-Host "✅ Manifest generated + signed + verified OK"
Write-Host "   $outJson"
Write-Host "   $outSig"
