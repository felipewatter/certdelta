# PowerShell 5.1+ / Windows: require local tests and GitHub CI before the release.
# Only a NEW GitHub repository is allowed. Existing repositories are never overwritten.
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
$repo = 'felipewatter/certdelta'
$tag = 'v0.1.0'
foreach ($command in @('git', 'gh', 'python')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Comando nao encontrado: $command"
    }
}
& gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Autentique o GitHub CLI: gh auth login' }
& gh repo view $repo *> $null
if ($LASTEXITCODE -eq 0) { throw "Repositorio $repo ja existe. Sem sobrescrita." }
if (Test-Path '.git') { throw 'Existe .git local: extraia o ZIP em uma pasta nova.' }

& python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'Pytest falhou: publicacao interrompida.' }
& python -m ruff check .
if ($LASTEXITCODE -ne 0) { throw 'Ruff ausente ou com falhas: publicacao interrompida.' }
& python -m pip_audit --strict
if ($LASTEXITCODE -ne 0) { throw 'Auditoria de dependencias falhou: publicacao interrompida.' }
& python -m build
if ($LASTEXITCODE -ne 0) { throw 'Build Python falhou: publicacao interrompida.' }
& python scripts/build_release.py
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar ZIP de release.' }
$archive = 'dist/certdelta-v0.1.0.zip'
$checksum = ((Get-Content 'dist/SHA256SUMS' -Raw).Trim() -split '\s+')[0]
$computed = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
if ($computed -ne $checksum) { throw 'Checksum SHA-256 nao corresponde ao ZIP de release.' }
Add-Type -AssemblyName System.IO.Compression
$zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $archive).Path)
try {
    if ($zip.Entries.Count -eq 0) { throw 'ZIP vazio.' }
    foreach ($entry in $zip.Entries) {
        if ($entry.FullName -match '(?i)\.(key|pfx|p12)$') { throw 'Material privado no ZIP de release.' }
    }
}
finally { $zip.Dispose() }

& git init -b main
if ($LASTEXITCODE -ne 0) { throw 'git init falhou.' }
& git add .
if ($LASTEXITCODE -ne 0) { throw 'git add falhou.' }
& git commit -m 'feat: initial CertDelta 0.1.0 release'
if ($LASTEXITCODE -ne 0) { throw 'git commit falhou; configure git user.name e git user.email.' }
& gh repo create $repo --public --source . --remote origin --push
if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar repositório GitHub.' }

$runId = ''
for ($attempt = 0; $attempt -lt 36; $attempt++) {
    $runId = ((& gh run list -R $repo --workflow ci.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId // empty') | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Erro ao consultar o GitHub Actions.' }
    if ($runId) { break }
    Start-Sleep -Seconds 5
}
if (-not $runId) { throw 'CI nao encontrado no GitHub: repository criado, mas release NAO criado.' }
& gh run watch $runId -R $repo --exit-status
if ($LASTEXITCODE -ne 0) { throw 'CI remoto falhou: release NAO criado.' }

& git tag -a $tag -m "CertDelta $tag"
if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar tag.' }
& git push origin $tag
if ($LASTEXITCODE -ne 0) { throw 'Falha ao enviar tag.' }
& gh release create $tag 'dist/certdelta-v0.1.0.zip' 'dist/SHA256SUMS' --repo $repo --title 'CertDelta v0.1.0' --notes-file 'CHANGELOG.md' --verify-tag
if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar release.' }
& gh release view $tag -R $repo
if ($LASTEXITCODE -ne 0) { throw 'Release nao foi encontrado apos publicacao.' }
Write-Host "Publicado e verificado: https://github.com/$repo/releases/tag/$tag"