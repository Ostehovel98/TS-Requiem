param(
  [Parameter(Mandatory=$true)]
  [string]$RepoRoot,

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

$outJson = Join-Path $RepoRoot "Requiem\manifest.json"
$outSig  = Join-Path $RepoRoot "Requiem\manifest.sig"
if (!(Test-Path $outJson)) { throw "Missing: $outJson" }
if (!(Test-Path $outSig)) { throw "Missing: $outSig" }

$jsonText = Get-Content -Raw -Encoding UTF8 $outJson
$sigB64 = (Get-Content -Raw -Encoding UTF8 $outSig) -replace '\s',''
$sigBytes = [Convert]::FromBase64String($sigB64)

$pubDer  = Read-PemDer $PublicKeyPemPath "PUBLIC KEY"
$ecdsaPub = [System.Security.Cryptography.ECDsa]::Create()
$bytesRead = 0
$ecdsaPub.ImportSubjectPublicKeyInfo($pubDer, [ref]$bytesRead) | Out-Null

$dataBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonText)
$ok = $ecdsaPub.VerifyData($dataBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

if ($ok) { Write-Host "✅ Verified OK" } else { throw "❌ Verify FAILED" }

