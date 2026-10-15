param(
  [Parameter(Mandatory = $true)][ValidateSet('Inspect', 'Sign', 'SignFolder', 'Verify')][string]$Mode,
  [Parameter(Mandatory = $true)][string]$ConfigPath,
  [Parameter(Mandatory = $true)][string]$FilePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-FileVersion([string]$Path) {
  $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
  if ([string]::IsNullOrWhiteSpace($info.ProductVersion)) { throw 'missing product version' }
  [pscustomobject]@{
    product_version = $info.ProductVersion
    file_version = $info.FileVersion
  }
}

function Test-WithinRoot([string]$Path, [string]$Root) {
  $candidate = [System.IO.Path]::GetFullPath($Path)
  $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\', '/'))
  $rootPrefix = $rootPath + [System.IO.Path]::DirectorySeparatorChar
  return $candidate.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase) -or $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Verify-Authenticode([string]$Path, [string]$Subject) {
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { throw 'invalid Authenticode signature' }
  if ($null -eq $signature.SignerCertificate) { throw 'missing Authenticode signer' }
  $actualName = ($signature.SignerCertificate.Subject -split ',\s*' | ForEach-Object { $_.Trim() -replace '^ST\s*=', 'S=' } | Sort-Object) -join ','
  $expectedName = ($Subject -split ',\s*' | ForEach-Object { $_.Trim() -replace '^ST\s*=', 'S=' } | Sort-Object) -join ','
  if ($actualName -ine $expectedName) { throw 'unexpected Authenticode subject' }
  if ($null -eq $signature.TimeStamperCertificate) { throw 'missing trusted timestamp' }
  [pscustomobject]@{
    subject = $signature.SignerCertificate.Subject
    timestamp_subject = $signature.TimeStamperCertificate.Subject
  }
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$file = [System.IO.Path]::GetFullPath($FilePath)
$inAllowedRoot = $false
foreach ($root in $config.allowed_roots) {
  if (Test-WithinRoot $file $root) { $inAllowedRoot = $true; break }
}
if (-not $inAllowedRoot) { throw 'signing path outside approved roots' }
if ($Mode -eq 'Inspect' -and -not (Test-WithinRoot $file $config.app_root)) { throw 'inspection path outside application directory' }
if ($Mode -eq 'SignFolder' -and -not $file.Equals([System.IO.Path]::GetFullPath($config.app_root), [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'signing directory outside application root'
}
if ($Mode -eq 'SignFolder') {
  if (-not [System.IO.Directory]::Exists($file)) { throw 'signing directory missing' }
} elseif (-not [System.IO.File]::Exists($file)) {
  throw 'signable file missing'
}
if ($Mode -in @('Sign', 'Verify') -and [System.IO.Path]::GetExtension($file) -notin @('.exe', '.dll', '.node')) {
  throw 'unsupported Authenticode file type'
}

switch ($Mode) {
  'Inspect' {
    $details = Read-FileVersion $file
    $details | ConvertTo-Json -Compress
  }
  { $_ -in 'Sign', 'SignFolder' } {
    $module = Get-Module -ListAvailable -Name ArtifactSigning | Where-Object { $_.Version -eq [version]'0.1.20' } | Select-Object -First 1
    if ($null -eq $module) { throw 'pinned Artifact Signing module unavailable' }
    Import-Module -Name $module.Path -Force
    if ($null -eq (Get-Command Invoke-ArtifactSigning -ErrorAction SilentlyContinue)) { throw 'Artifact Signing command unavailable' }

    $parameters = @{
      Endpoint = $config.azure.endpoint
      CodeSigningAccountName = $config.azure.account
      CertificateProfileName = $config.azure.certificate_profile
      FileDigest = 'SHA256'
      TimestampRfc3161 = 'http://timestamp.acs.microsoft.com'
      TimestampDigest = 'SHA256'
      ExcludeEnvironmentCredential = $true
      ExcludeWorkloadIdentityCredential = $true
      ExcludeManagedIdentityCredential = $true
      ExcludeSharedTokenCacheCredential = $true
      ExcludeVisualStudioCredential = $true
      ExcludeVisualStudioCodeCredential = $true
      ExcludeAzureCliCredential = $false
      ExcludeAzurePowerShellCredential = $true
      ExcludeAzureDeveloperCliCredential = $true
      ExcludeInteractiveBrowserCredential = $true
    }
    if ($Mode -eq 'SignFolder') {
      $parameters.FilesFolder = $file
      $parameters.FilesFolderFilter = 'exe,EXE,dll,DLL,node,NODE'
      $parameters.FilesFolderRecurse = $true
    } else {
      $parameters.Files = $file
    }
    Invoke-ArtifactSigning @parameters

    if ($Mode -eq 'Sign') { Verify-Authenticode $file $config.azure.subject | ConvertTo-Json -Compress }
  }
  'Verify' {
    Verify-Authenticode $file $config.azure.subject | ConvertTo-Json -Compress
  }
}
