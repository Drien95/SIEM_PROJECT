<#
.SYNOPSIS
    Famille 02 : verrouillage de comptes (CIS Windows 11 Enterprise v3.0.0, section 1.2).

.DESCRIPTION
    Risque : ÉLEVÉ (verrouillage de la VM). Protégée par le garde-fou Assert-SafeLockout :
      - exige -AcceptLockoutRisk ;
      - exige deux comptes administrateurs locaux activés (compte de secours) ;
      - affiche la procédure de déverrouillage AVANT d'appliquer ;
      - demande de taper OUI (sauf -Force).

    Effet sur le lab : le scénario 1 (brute force SMB depuis Kali) verrouillera le compte
    visé au 5e échec (événement 4740). C'est une détection intéressante en soi, mais pour
    rejouer le scénario 1 tel quel, faire d'abord -Rollback (ou net accounts
    /lockoutthreshold:0).

    1.2.3 « Allow Administrator account lockout » (Manual dans la politique Wazuh) n'est
    appliqué qu'avec -IncludeAdministratorLockout : il rend verrouillable le compte
    Administrateur intégré (RID 500), désactivé par défaut sur Windows 11. Nom de clé
    secedit « AllowAdministratorLockout » : à valider sur la VM (Windows 11 22H2 et plus).

    Statut : à valider sur la VM.

.EXAMPLE
    .\02-account-lockout.ps1                              # dry-run
    .\02-account-lockout.ps1 -Apply -AcceptLockoutRisk    # applique après garde-fou
    .\02-account-lockout.ps1 -Rollback                    # revient à l'état sauvegardé
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Rollback,
    [string]$BackupPath,
    [string]$RunDir,
    [switch]$AcceptLockoutRisk,
    [switch]$Force,
    [switch]$Describe,
    [switch]$IncludeAdministratorLockout
)

# Ordre important : le seuil (LockoutBadCount) doit précéder la durée et la remise à
# zéro dans le modèle secedit, et la remise à zéro doit rester <= durée (15 <= 15).
$settings = @(
    # 1.2.2 : verrouillage après 5 échecs au plus, mais pas 0 (0 = jamais de verrouillage).
    @{ Cis = '1.2.2'; Sca = 26006; Title = 'Seuil de verrouillage'; Type = 'SecPol'; Key = 'LockoutBadCount'; Value = 5; Compare = 'range'; Min = 1; Max = 5 }
    # 1.2.4 : le compteur d'échecs repart de zéro après 15 minutes.
    @{ Cis = '1.2.4'; Sca = 26007; Title = 'Réinitialisation du compteur (minutes)'; Type = 'SecPol'; Key = 'ResetLockoutCount'; Value = 15; Compare = 'ge' }
    # 1.2.1 : un compte verrouillé le reste 15 minutes (puis se débloque seul).
    @{ Cis = '1.2.1'; Sca = 26005; Title = 'Durée de verrouillage (minutes)'; Type = 'SecPol'; Key = 'LockoutDuration'; Value = 15; Compare = 'ge' }
)
if ($IncludeAdministratorLockout) {
    # 1.2.3 : l'Administrateur intégré peut lui aussi être verrouillé. Check SCA manuel.
    $settings += @{ Cis = '1.2.3'; Sca = $null; Title = 'Verrouillage du compte Administrateur'; Type = 'SecPol'; Key = 'AllowAdministratorLockout'; Value = 1; Compare = 'eq' }
}

$Family = [ordered]@{
    Id           = '02'
    Name         = 'Verrouillage de comptes (CIS 1.2)'
    Risk         = 'Élevé (lockout)'
    LockoutGuard = $true
    Settings     = $settings
}

if ($Describe) { return $Family }

Import-Module (Join-Path $PSScriptRoot '..\HardeningLib.psm1') -Force
Invoke-HardeningFamily -Family $Family -Apply:$Apply -Rollback:$Rollback -BackupPath $BackupPath `
    -RunDir $RunDir -AcceptLockoutRisk:$AcceptLockoutRisk -Force:$Force
