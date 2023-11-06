if (-not(Test-Path -Path "services/gateway/.env" -PathType Leaf)) {
    throw "Please create .env file from .env.example inside services/gateway/"
}

Get-Content services/gateway/.env | ForEach-Object {
    $name, $value = $_.split('=')
    if ([string]::IsNullOrWhiteSpace($name) -Or $name.Contains('#')) {
        continue
    }
    Set-Content env:\$name $value
}

if ($null -eq (Get-Command "rover.exe" -ErrorAction SilentlyContinue)) {
    Invoke-WebRequest 'https://rover.apollo.dev/win/latest' | Invoke-Expression
}

if ($null -eq $env:USER_SERVICE_LOCATION) {
    throw "Missing USER_SERVICE_LOCATION environment variable"
}

$supergraphConfig = Get-Content -Path 'supergraph-config.yaml'
$compiledConfig = $supergraphConfig -replace '{USER_SERVICE_LOCATION}', $env:USER_SERVICE_LOCATION
$compiledConfig | Set-Content -Path 'supergraph-config.compiled.yaml'

& rover supergraph compose --config ./supergraph-config.compiled.yaml --output services/gateway/supergraph.graphql

Remove-Item 'supergraph-config.compiled.yaml'