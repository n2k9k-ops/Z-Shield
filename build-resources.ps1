# =============================================================================
# build-resources.ps1 — regenere le ZIP telechargeable du panel a partir des
# SOURCES reelles (zshield-ac + zshield-agent), a CHAQUE push.
#
# Pourquoi : le depot git deploye sur Render = zshield-dashboard uniquement.
# Les ressources (zshield-ac, zshield-agent) sont a cote, HORS du depot : Render
# ne les voit pas au build. On regenere donc le .zip ICI (sur ton PC, ou tout le
# monorepo existe) juste avant le commit, pour que le fichier servi soit toujours
# a jour. Aucune dependance : Compress-Archive est integre a Windows.
#
# Sortie : apps\web\public\zshield-ac.zip  (contient les dossiers zshield-ac\ et
# zshield-agent\, tests exclus). Render sert ce fichier tel quel.
# =============================================================================
$ErrorActionPreference = 'Stop'

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path   # ...\zshield-dashboard
$root   = Split-Path -Parent $here                          # ...\Z-Shield (monorepo)
$public = Join-Path $here 'apps\web\public'
$dest   = Join-Path $public 'zshield-ac.zip'

# Ressources livrees dans le paquet (doit correspondre aux etapes d'install du panel).
$resources = @('zshield-ac','zshield-agent')

$stage = Join-Path $env:TEMP ("zshield-pkg-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    foreach ($r in $resources) {
        $src = Join-Path $root $r
        if (-not (Test-Path $src)) { throw "Ressource introuvable : $src" }
        Copy-Item $src (Join-Path $stage $r) -Recurse
    }

    # Ne jamais livrer : tests, historique git, dependances.
    Get-ChildItem $stage -Recurse -Directory -Force |
        Where-Object { $_.Name -in @('tests', '.git', 'node_modules') } |
        Sort-Object FullName -Descending |
        ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }

    if (-not (Test-Path $public)) { New-Item -ItemType Directory -Path $public | Out-Null }
    if (Test-Path $dest) { Remove-Item $dest -Force }

    # -Path "$stage\*" => les dossiers zshield-ac\ et zshield-agent\ sont a la racine du zip.
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $dest -Force

    $kb = [math]::Round((Get-Item $dest).Length / 1KB)
    Write-Host "[build-resources] zshield-ac.zip regenere ($kb Ko) : $($resources -join ' + ')"
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
