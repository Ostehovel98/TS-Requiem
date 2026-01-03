param(
  [Parameter(Mandatory=$true)]
  [string]$RepoRoot,

  [Parameter(Mandatory=$true)]
  [string]$PrivateKeyPemPath,

  [Parameter(Mandatory=$true)]
  [string]$PublicKeyPemPath
)

$ErrorActionPreference = "Stop"

function Read-PemDer([string]$pemPath, [string]$label) {
  $pem = Get-Content -Raw -Encoding UTF8 $pemPath
  $begin = "-----BEGIN $label-----"
  $end   = "-----END $label-----"
  $i = $pem.IndexOf($begin)
  if ($i -lt 0) { throw "PEM begin label not found: $begin" }
  $i += $begin.Length
  $j = $pem.IndexOf($end, $i)
  if ($j -lt 0) { throw "PEM end label not found: $end" }
  $b64 = ($pem.Substring($i, $j - $i) -replace '\s','')
  return [Convert]::FromBase64String($b64)
}

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

# Build canonical manifest object (stable key order)
$publishedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$manifest = [ordered]@{
  product      = [string]$values.product
  minVersion   = [string]$values.minVersion
  currentVersion = [string]$values.currentVersion
  releaseKeyId = [string]$values.releaseKeyId
  message      = [string]$values.message
  publishedUtc = $publishedUtc
}

# Canonical JSON: minified, LF newline, UTF-8 no BOM
# ConvertTo-Json adds indentation; we minify deterministically.
$jsonPretty = ($manifest | ConvertTo-Json -Depth 5)
$jsonMin = ($jsonPretty -replace "(\r\n|\r|\n)","`n") `
                  -replace ":\s+"," :" `
                  -replace "\s+"," " `
                  -replace "\s*{\s*","{" `
                  -replace "\s*}\s*","}" `
                  -replace "\s*\[\s*","\[" `
                  -replace "\s*\]\s*","]" `
                  -replace "\s*,\s*","," `
                  -replace "\s*:\s*",":" `
                  -replace " \}","}" `
                  -replace "{ ","{" `
                  -replace " \[","\[" `
                  -replace "\] ","]"

# Ensure final is truly compact (no accidental double spaces)
while ($jsonMin -match "  ") { $jsonMin = $jsonMin -replace "  "," " }

# Always end with a single LF (so bytes are stable)
$jsonMin = $jsonMin.Trim() + "`n"

Write-Utf8NoBom $outJson $jsonMin

# Load keys
$privDer = Read-PemDer $PrivateKeyPemPath "EC PRIVATE KEY"
$pubDer  = Read-PemDer $PublicKeyPemPath "PUBLIC KEY"

# Import keys into ECDsa
$ecdsaPriv = [System.Security.Cryptography.ECDsa]::Create()
$bytesRead = 0
$ecdsaPriv.ImportECPrivateKey($privDer, [ref]$bytesRead) | Out-Null

$ecdsaPub = [System.Security.Cryptography.ECDsa]::Create()
$bytesRead2 = 0
$ecdsaPub.ImportSubjectPublicKeyInfo($pubDer, [ref]$bytesRead2) | Out-Null

# Sign bytes (DER ECDSA signature)
$dataBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonMin)
$sigBytes = $ecdsaPriv.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

# Write base64 signature as one line + LF
$sigB64 = [Convert]::ToBase64String($sigBytes) + "`n"
Write-Utf8NoBom $outSig $sigB64

# Verify immediately (this is the “idiot proof” guardrail)
$ok = $ecdsaPub.VerifyData($dataBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
if (-not $ok) { throw "Signature verification FAILED right after signing (should never happen)." }

Write-Host "✅ Manifest generated + signed + verified OK"
Write-Host "   $outJson"
Write-Host "   $outSig"
