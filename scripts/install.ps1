# Installs MCPBytes Vault from the latest GitHub release, for the current user:
#   irm https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download/install.ps1 | iex
# Private files instead of Credential Manager:  $env:MCPBYTES_VAULT_STORE = 'file'; irm ... | iex
# It downloads the Windows archive, checks it against the release's SHA256SUMS.txt, unpacks it in a
# temporary folder and runs `mcpbytes-vault install`, which copies the program into place.
& {
    $ErrorActionPreference = 'Stop'
    $release = if ($env:MCPBYTES_VAULT_RELEASE_URL) { $env:MCPBYTES_VAULT_RELEASE_URL } else { 'https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download' }
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'MCPBytes Vault needs 64-bit Windows.' }
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $archive = 'mcpbytes-vault-windows-x64.zip'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('mcpbytes-vault-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        foreach ($file in $archive, 'SHA256SUMS.txt') {
            Invoke-WebRequest -UseBasicParsing -Uri "$release/$file" -OutFile (Join-Path $tmp $file)
        }
        $expected = Get-Content (Join-Path $tmp 'SHA256SUMS.txt') | ForEach-Object { $hash, $name = -split $_; if ($name -eq $archive) { $hash } }
        $actual = (Get-FileHash (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $expected -or $expected -ne $actual) { throw "$archive does not match SHA256SUMS.txt; nothing was installed." }
        Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp
        $exe = Get-ChildItem -Path $tmp -Recurse -Filter 'mcpbytes-vault.exe' | Select-Object -First 1
        $options = if ($env:MCPBYTES_VAULT_STORE) { @('--store', $env:MCPBYTES_VAULT_STORE) } else { @() }
        & $exe.FullName install @options
        if ($LASTEXITCODE -ne 0) { throw 'mcpbytes-vault install failed.' }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
