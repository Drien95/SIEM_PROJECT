<#
.SYNOPSIS
    MODÈLE de famille. Copier en NN-nom-court.ps1 (NN = numéro suivant), remplir $Family.

.DESCRIPTION
    Le fichier commençant par « _ » est ignoré par l'orchestrateur.

    Étapes pour ajouter une famille :
      1. Choisir une section CIS cohérente et à risque maîtrisé ; noter pour chaque
         réglage la référence CIS et l'id du check SCA dans
         ruleset/sca/windows/cis_win11_enterprise.yml (Wazuh v4.14.0).
      2. Reprendre exactement la cible et l'opérateur du check SCA (compare >= 14 -> 'ge').
      3. Commenter chaque réglage : ce qu'il fait, pourquoi, ce qu'il casse éventuellement.
      4. Risque de verrouillage ou de perte d'accès -> LockoutGuard = $true (ou un garde-fou
         dédié dans HardeningLib.psm1).
      5. Tester : dry-run, -Apply, relance SCA, -Rollback, puis consigner le résultat dans
         le README (« Résultats dans notre lab »).

    Types de réglage et champs :
      SecPol   : Key = clé de [System Access] (secedit /export pour voir les noms).
      Registry : Path = 'HKLM:\...', Name, ValueType ('DWord', 'String'…).
      AuditPol : Guid = '{GUID de la sous-catégorie}', Value = bits (1 succès, 2 échec).
    Opérateurs Compare : 'eq', 'ge', 'le', 'range' (avec Min et Max), 'include' (bits).
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Rollback,
    [string]$BackupPath,
    [string]$RunDir,
    [switch]$AcceptLockoutRisk,
    [switch]$Force,
    [switch]$Describe
)

$Family = [ordered]@{
    Id           = 'NN'
    Name         = 'Nom de la famille (CIS x.y)'
    Risk         = 'Faible'
    LockoutGuard = $false
    Settings     = @(
        # x.y.z : ce que fait le réglage et pourquoi.
        @{ Cis = 'x.y.z'; Sca = 26000; Title = 'Intitulé court'; Type = 'Registry'
           Path = 'HKLM:\SOFTWARE\Exemple'; Name = 'Valeur'; ValueType = 'DWord'; Value = 1; Compare = 'eq' }
    )
}

if ($Describe) { return $Family }

Import-Module (Join-Path $PSScriptRoot '..\HardeningLib.psm1') -Force
Invoke-HardeningFamily -Family $Family -Apply:$Apply -Rollback:$Rollback -BackupPath $BackupPath `
    -RunDir $RunDir -AcceptLockoutRisk:$AcceptLockoutRisk -Force:$Force
