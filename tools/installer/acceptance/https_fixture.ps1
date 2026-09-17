param([Parameter(Mandatory=$true)][string]$Assets, [Parameter(Mandatory=$true)][string]$Log)
$ErrorActionPreference = 'Stop'
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add('https://github.com:443/')
$listener.Start()
$requests = @()
try {
    $config = Get-Content -Raw (Join-Path $Assets 'installer.json') | ConvertFrom-Json
    if ($config.schema -eq 1) {
        # Schema-1 installers share the OS payload's release repository: Couch
        # under its current or transferred name, never another owner.
        $repository = ([Uri]$config.payload.url).AbsolutePath -replace '^(/[^/]+/[^/]+)/releases/download/.*$', '$1'
        if ($repository -cnotin @('/dangerouslaser/couch', '/Couch-OS/couch')) { throw 'Unsupported fixture OS repository' }
        $releasePath = $repository + '/releases/download/' + $config.version
    } elseif ($config.schema -eq 2) {
        $releasePath = ([Uri]$config.installer.release_url).AbsolutePath
    } else {
        throw 'Unsupported fixture descriptor schema'
    }
    foreach ($expected in @('couch-installer-host-windows-x64.exe', 'couch-installer-tui-windows-x64.exe', 'installer.json')) {
        $context = $listener.GetContext()
        $path = $releasePath + '/' + $expected
        if (-not [Net.IPAddress]::IsLoopback($context.Request.RemoteEndPoint.Address) -or $context.Request.Url.AbsolutePath -ne $path -or $context.Request.HttpMethod -ne 'GET') {
            $context.Response.StatusCode = 403; $context.Response.Close(); throw 'Unexpected fixture request'
        }
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Assets $expected))
        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $context.Response.Close()
        $requests += $path
    }
    $requests | ConvertTo-Json | Set-Content -LiteralPath $Log -Encoding UTF8
} finally { $listener.Close() }
