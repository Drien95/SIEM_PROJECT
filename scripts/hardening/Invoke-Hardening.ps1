<#
.SYNOPSIS
    Orchestrateur du durcissement CIS de l'agent Windows 11 du lab (SIEM-Win11).

.DESCRIPTION
    Enchaîne les familles de families\NN-*.ps1 :
      1. contrôles préalables (administrateur, outils, service Wazuh, poste en domaine) ;
      2. en mode -Apply : sauvegarde GLOBALE (secedit toutes zones + auditpol) en plus des
         sauvegardes par famille ;
      3. exécution de chaque famille choisie (dry-run par défaut) ;
      4. rapport de vérification : console, report.csv (séparateur « ; » pour Excel FR) et
         report.md, dans C:\ProgramData\SIEM-Hardening\runs\<date>\ ;
      5. option -Rescan : redémarre l'agent Wazuh pour déclencher un nouveau scan SCA
         (scan_on_start = yes par défaut).

    Jamais d'application silencieuse : sans -Apply, rien n'est modifié. La famille 02
    (verrouillage) est en plus ignorée tant que -AcceptLockoutRisk n'est pas passé.

    Code de sortie : 0 si tout est PASS / DRYRUN / ROLLBACK, 1 si un FAIL ou une erreur.
    Statut : à valider sur la VM.

.PARAMETER Families
    Numéros des familles à traiter (ex. 01,03). Par défaut : toutes.
.PARAMETER Apply
    Applique réellement. Sans ce switch : dry-run.
.PARAMETER Rollback
    Restaure les familles (dans l'ordre inverse) depuis la sauvegarde de -FromRun, ou à
    défaut depuis la dernière sauvegarde appliquée de chaque famille.
.PARAMETER FromRun
    Dossier d'une exécution précédente (runs\AAAAMMJJ-HHmmss) dont on restaure les sauvegardes.
.PARAMETER AcceptLockoutRisk
    Autorise la famille 02 (le garde-fou vérifie quand même le compte de secours).
.PARAMETER IncludeAdministratorLockout
    Transmis à la famille 02 (CIS 1.2.3).
.PARAMETER Force
    Pas de confirmation tapée « OUI » (mode automatisé). Les autres garde-fous restent actifs.
.PARAMETER Rescan
    Redémarre WazuhSvc après -Apply ou -Rollback pour relancer le scan SCA.

.EXAMPLE
    .\Invoke-Hardening.ps1                                  # dry-run de toutes les familles
    .\Invoke-Hardening.ps1 -Families 01 -Apply -Rescan      # applique la famille 01, relance le SCA
    .\Invoke-Hardening.ps1 -Families 02 -Apply -AcceptLockoutRisk
    .\Invoke-Hardening.ps1 -Rollback -Families 02 -Rescan   # annule la famille 02
#>
[CmdletBinding()]
param(
    [string[]]$Families,
    [switch]$Apply,
    [switch]$Rollback,
    [string]$FromRun,
    [switch]$AcceptLockoutRisk,
    [switch]$IncludeAdministratorLockout,
    [switch]$Force,
    [switch]$Rescan
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HardeningLib.psm1') -Force
Assert-Administrator
if ($Apply -and $Rollback) { throw '-Apply et -Rollback sont exclusifs.' }

$runDir = Initialize-HardeningRun
$mode = if ($Rollback) { 'ROLLBACK' } elseif ($Apply) { 'APPLY' } else { 'DRY-RUN' }
Write-HardeningLog -Level STEP -Message "Durcissement CIS - mode $mode - dossier $runDir"

#region Contrôles préalables
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-HardeningLog -Message "Machine $env:COMPUTERNAME - $($os.Caption) build $($os.BuildNumber) - utilisateur $env:USERNAME"
if ($cs.PartOfDomain) {
    Write-HardeningLog -Level WARN -Message "Poste membre du domaine $($cs.Domain) : une GPO peut écraser ces réglages locaux."
}
foreach ($tool in 'secedit.exe', 'auditpol.exe') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool introuvable." }
}
$wazuh = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($wazuh) { Write-HardeningLog -Message "Agent Wazuh (WazuhSvc) : $($wazuh.Status)" }
else { Write-HardeningLog -Level WARN -Message 'Service WazuhSvc absent : -Rescan sera sans effet.' }
#endregion

#region Choix des familles
# Les familles sont les fichiers NN-*.ps1 ; _template.ps1 est ignoré.
$scripts = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'families') -Filter '*.ps1' |
    Where-Object { $_.Name -match '^\d{2}-' } | Sort-Object Name)
if ($Families) {
    # « -Families 01,03 » sans guillemets arrive en nombres (1, 3) : on remet sur deux chiffres.
    $wanted = @($Families | ForEach-Object { $_.Split(',') } | ForEach-Object { '{0:D2}' -f [int]$_.Trim() })
    $scripts = @($scripts | Where-Object { $wanted -contains $_.Name.Substring(0, 2) })
}
if ($scripts.Count -eq 0) { throw "Aucune famille trouvée pour : $($Families -join ', ')" }
if ($Rollback) { [array]::Reverse($scripts) }
Write-HardeningLog -Message ('Familles : ' + (($scripts | ForEach-Object { $_.BaseName }) -join ', '))
#endregion

#region Sauvegarde globale (filet de sécurité manuel, en plus des sauvegardes par famille)
if ($Apply) {
    $global = Join-Path $runDir 'global'
    New-Item -ItemType Directory -Path $global -Force | Out-Null
    & secedit.exe /export /cfg (Join-Path $global 'secpol-all.inf') /quiet | Out-Null
    & auditpol.exe /backup "/file:$(Join-Path $global 'auditpol.csv')" | Out-Null
    if (-not (Test-Path (Join-Path $global 'secpol-all.inf'))) { throw 'Sauvegarde globale impossible : arrêt avant toute modification.' }
    Write-HardeningLog -Level OK -Message "Sauvegarde globale : $global"
}
#endregion

#region Exécution
$results = @()
foreach ($file in $scripts) {
    $family = & $file.FullName -Describe
    $params = @{ RunDir = $runDir; Force = [bool]$Force; AcceptLockoutRisk = [bool]$AcceptLockoutRisk }
    if ($Apply) { $params.Apply = $true }
    if ($Rollback) {
        $params.Rollback = $true
        if ($FromRun) {
            $candidate = Join-Path (Join-Path $FromRun 'backups') $family.Id
            if (Test-Path $candidate) { $params.BackupPath = $candidate }
            else { Write-HardeningLog -Level WARN -Message "Famille $($family.Id) absente de $FromRun : ignorée."; continue }
        }
    }
    if ((Get-Command $file.FullName).Parameters.ContainsKey('IncludeAdministratorLockout')) {
        $params.IncludeAdministratorLockout = [bool]$IncludeAdministratorLockout
    }
    if ($Apply -and $family.LockoutGuard -and -not $AcceptLockoutRisk) {
        Write-HardeningLog -Level WARN -Message "Famille $($family.Id) ignorée : risque de verrouillage, ajouter -AcceptLockoutRisk (voir README)."
        $results += [pscustomobject]@{ Famille = $family.Id; CIS = '-'; SCA = '-'; Reglage = $family.Name; Attendu = '-'
            Avant = '-'; Apres = '-'; Action = 'Ignorée (-AcceptLockoutRisk absent)'; Statut = 'SKIPPED' }
        continue
    }
    try { $results += @(& $file.FullName @params) }
    catch {
        Write-HardeningLog -Level ERROR -Message "Famille $($family.Id) : $($_.Exception.Message)"
        $results += [pscustomobject]@{ Famille = $family.Id; CIS = '-'; SCA = '-'; Reglage = $family.Name; Attendu = '-'
            Avant = '-'; Apres = '-'; Action = $_.Exception.Message; Statut = 'ERROR' }
    }
}
#endregion

#region Relance du scan SCA
if ($Rescan -and ($Apply -or $Rollback) -and $wazuh) {
    Write-HardeningLog -Level STEP -Message 'Redémarrage de WazuhSvc pour relancer le scan SCA.'
    try { Restart-Service -Name WazuhSvc -ErrorAction Stop } catch { Write-HardeningLog -Level WARN -Message $_.Exception.Message }
    # Un redémarrage raté peut laisser l'agent ARRÊTÉ (vu dans le lab) : on vérifie et on relance.
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Seconds 2; $status = (Get-Service WazuhSvc).Status } while ($status -ne 'Running' -and (Get-Date) -lt $deadline)
    if ($status -ne 'Running') {
        Write-HardeningLog -Level WARN -Message "WazuhSvc est $status : tentative de Start-Service."
        Start-Service -Name WazuhSvc
        $status = (Get-Service WazuhSvc).Status
    }
    $level = if ($status -eq 'Running') { 'OK' } else { 'ERROR' }
    Write-HardeningLog -Level $level -Message "WazuhSvc : $status. Résultat SCA dans le dashboard d'ici quelques minutes (Configuration Assessment)."
}
#endregion

#region Rapport
$csv = Join-Path $runDir 'report.csv'
$md = Join-Path $runDir 'report.md'
$results | Export-Csv -Path $csv -NoTypeInformation -Delimiter ';' -Encoding UTF8

$counts = $results | Group-Object Statut | ForEach-Object { "$($_.Name)=$($_.Count)" }
$lines = @(
    "# Rapport de durcissement CIS - $env:COMPUTERNAME"
    ''
    "- Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "- Mode : $mode"
    "- Bilan : $($counts -join ', ')"
    ''
    '| Famille | CIS | SCA | Réglage | Attendu | Avant | Après | Action | Statut |'
    '|---|---|---|---|---|---|---|---|---|'
)
foreach ($r in $results) {
    $lines += "| $($r.Famille) | $($r.CIS) | $($r.SCA) | $($r.Reglage) | $($r.Attendu) | $($r.Avant) | $($r.Apres) | $($r.Action) | $($r.Statut) |"
}
$lines | Set-Content -Path $md -Encoding UTF8

$results | Format-Table Famille, CIS, SCA, Reglage, Avant, Apres, Statut -AutoSize | Out-String -Width 200 | Write-Host
Write-HardeningLog -Level STEP -Message "Bilan : $($counts -join ', ')"
Write-HardeningLog -Message "Rapport : $md"
Write-HardeningLog -Message "Journal : $(Join-Path $runDir 'hardening.log')"
if ($Apply -and (Test-Path (Join-Path $runDir 'backups'))) { Write-HardeningLog -Message "Annuler cette exécution : .\Invoke-Hardening.ps1 -Rollback -FromRun `"$runDir`"" }
#endregion

if (@($results | Where-Object { $_.Statut -in 'FAIL', 'ERROR' }).Count -gt 0) { exit 1 }
exit 0
