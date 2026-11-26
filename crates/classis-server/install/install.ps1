#Requires -Version 5.1
<#
  Enrols this host from the Server that served this script.

  The same install the .msi does, from a URL: the Server hands out the Client archive it already
  hands a fleet self-update, and the install itself is the Client's own `service install`, never a
  second one. Like the .msi it names no root, so the layout and the state go to the platform
  default, `%ProgramData%\classis`, and nothing is written into `Program Files`.

  TLS was settled before this ran: the host fetched this file over it. So nothing here provisions a
  CA or relaxes a check — the Server is verified against the trust the host already has, at TLS 1.3,
  with no redirect.

  The enrolment key is an argument to `enrol` and never part of a URL, so it cannot reach a proxy's
  or the Server's access log. It does appear in that command's arguments, exactly as it does for an
  operator who types `classis enrol` by hand.

  Usage: .\install.ps1 -Url <base-url> -Key <enrolment-key>
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string]$Key
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Base = ''
$Endpoint = ''

function Stop-Install {
    param([string]$Message)
    throw "classis install: $Message"
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Install 'run this from an elevated PowerShell'
    }
}

# TLS 1.3 and nothing else, which is a floor rather than an extra option. The enum is checked first
# because a host whose .NET has no Tls13 must refuse rather than quietly handshake at 1.2.
function Assert-Tls13 {
    if ('Tls13' -notin [Net.SecurityProtocolType].GetEnumNames()) {
        Stop-Install 'this PowerShell offers no TLS 1.3 — install .NET Framework 4.8'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
}

function Assert-Url {
    if (-not $Url) { Stop-Install '-Url is required' }
    $parsed = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed)) {
        Stop-Install "$Url is not an absolute URL"
    }
    if ($parsed.Scheme -ne 'http' -and $parsed.Scheme -ne 'https') {
        Stop-Install "$Url must start with https://"
    }
    # The rule `enrol` applies to its own base URL (`enrolment::route`): a scheme, a host and
    # perhaps a path, with no credentials, query or fragment.
    if ($parsed.UserInfo -or $parsed.Query -or $parsed.Fragment) {
        Stop-Install "$Url must be a scheme, a host and perhaps a path"
    }
    # A name never counts as loopback, `localhost` included, because a name can be made to resolve
    # anywhere. Same rule as `opamp::endpoint::is_loopback_literal`.
    $hostName = $parsed.Host.TrimStart('[').TrimEnd(']')
    if ($parsed.Scheme -eq 'http' -and $hostName -notin @('127.0.0.1', '::1')) {
        Stop-Install "${Url}: plaintext is for 127.0.0.1 and ::1 alone — use https://"
    }
    $script:Base = $Url.TrimEnd('/')
    # `https` becomes `wss` and `http` becomes `ws` under one anchored rule, and the OpAMP path is
    # what `service install` writes into `supervisor.toml`.
    $script:Endpoint = ($script:Base -replace '^http', 'ws') + '/v1/opamp'
}

# The key's own alphabet: `cle1_<space>_<secret>`, letters, digits, `-` and `_`
# (`classis_core::enrolment_key`). The first character is never a dash, which is what keeps the key
# an argument of `enrol` and never one of its flags.
function Assert-Key {
    if (-not $Key) { Stop-Install '-Key is required' }
    if ($Key -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
        Stop-Install 'the enrolment key holds a character a key may not hold'
    }
}

function Require-Tool {
    param([string]$Name)
    if (-not (Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue)) {
        Stop-Install "this host has no $Name"
    }
}

# The release builds one Windows target, `amd64`; PROCESSOR_ARCHITEW6432 is the real machine under
# a 32-bit PowerShell.
function Get-Arch {
    if (-not [Environment]::Is64BitOperatingSystem) {
        Stop-Install 'the Client ships 64-bit Windows only'
    }
    $machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($machine -ne 'AMD64') { Stop-Install "no Client build for $machine" }
    'amd64'
}

# `AllowAutoRedirect` off refuses a redirect and 200 says the answer is the Client. `HttpWebRequest`
# because `-OutFile` writes the file but returns no status to check, while `-PassThru`, which does,
# can leave that file empty. TLS stays where `Assert-Tls13` put it; the body is streamed to disk.
function Get-Archive {
    param([string]$Uri, [string]$Destination)
    [Net.HttpWebRequest]$request = [Net.WebRequest]::Create($Uri)
    $request.AllowAutoRedirect = $false
    $response = $null
    $file = $null
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { Stop-Install "$Uri answered $([int]$response.StatusCode)" }
        $file = [IO.File]::Create($Destination)
        $response.GetResponseStream().CopyTo($file)
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($file) { $file.Dispose() }
    }
}

# Only the one member the release workflow packs, and never a path the archive chose: an archive
# that holds anything else is refused before a byte of it is written.
function Expand-Client {
    param([string]$Archive, [string]$Destination)
    $members = & tar.exe -tzf $Archive
    if ($LASTEXITCODE -ne 0) { Stop-Install "$Archive is not a .tar.gz" }
    if (@($members).Count -ne 1 -or $members -notcontains 'supervisor.exe') {
        Stop-Install 'the archive holds something other than the Client'
    }
    & tar.exe -xzf $Archive -C $Destination -- 'supervisor.exe'
    if ($LASTEXITCODE -ne 0) { Stop-Install 'cannot unpack the Client' }
}

Assert-Elevated
Assert-Url
Assert-Key
Require-Tool 'tar.exe'
if ($Base -like 'https://*') { Assert-Tls13 }
# Re-registration is `classis service install` and `classis enrol`, not a second delivery of the
# program: refusing here is what keeps this script from swinging the `current` pointer of a host an
# operator already manages.
if (Get-Service -Name 'classis' -ErrorAction SilentlyContinue) {
    Stop-Install 'this host is registered already — run classis enrol, or remove the service first'
}
$arch = Get-Arch
$tmp = Join-Path $env:TEMP ('classis-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $archive = Join-Path $tmp 'client.tar.gz'
    Get-Archive -Uri "$Base/v1/install/windows/$arch" -Destination $archive
    Expand-Client -Archive $archive -Destination $tmp
    $program = Join-Path $tmp 'supervisor.exe'
    & $program service install --endpoint $Endpoint
    if ($LASTEXITCODE -ne 0) { Stop-Install "service install failed with exit code $LASTEXITCODE" }
    & $program enrol $Base $Key
    if ($LASTEXITCODE -ne 0) { Stop-Install "enrol failed with exit code $LASTEXITCODE" }
    Write-Output 'Installed and enrolled: the service runs and starts at boot.'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
