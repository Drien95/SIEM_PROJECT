<#
.SYNOPSIS
    Famille 01 : politique de mots de passe (CIS Windows 11 Enterprise v3.0.0, section 1.1).

.DESCRIPTION
    Risque : FAIBLE. Aucun verrouillage possible ; les nouvelles exigences (longueur,
    complexité) s'appliquent au PROCHAIN changement de mot de passe, pas aux mots de passe
    actuels. Attention à l'âge maximal (365 jours) : un compte dont le mot de passe a plus
    d'un an devra le changer à la prochaine ouverture de session (sauf « le mot de passe
    n'expire jamais »).

    Déjà validé à la main sur la VM le 2026-10-25 pour 1.1.4 (check SCA 26003 passé à
    Passed). Le reste : à valider.

    Les checks SCA 1.1.5 (complexité) et 1.1.7 (chiffrement réversible) sont marqués
    « Not Implemented » dans la politique Wazuh : on les applique quand même (CIS), sans
    retour dans le tableau de bord SCA.

.EXAMPLE
    .\01-password-policy.ps1              # dry-run : montre ce qui changerait
    .\01-password-policy.ps1 -Apply       # sauvegarde, applique, vérifie
    .\01-password-policy.ps1 -Rollback    # restaure la dernière sauvegarde de cette famille
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

# Un réglage = référence CIS, id du check SCA Wazuh (cis_win11_enterprise.yml v4.14.0),
# intitulé, type, cible et comparaison (mêmes opérateurs que le check SCA).
$Family = [ordered]@{
    Id           = '01'
    Name         = 'Politique de mots de passe (CIS 1.1)'
    Risk         = 'Faible'
    LockoutGuard = $false
    Settings     = @(
        # 1.1.1 : on ne peut pas réutiliser ses 24 derniers mots de passe.
        @{ Cis = '1.1.1'; Sca = 26000; Title = 'Historique des mots de passe'; Type = 'SecPol'; Key = 'PasswordHistorySize'; Value = 24; Compare = 'ge' }
        # 1.1.2 : expiration à 365 jours maximum, mais pas 0 (0 = n'expire jamais).
        @{ Cis = '1.1.2'; Sca = 26001; Title = 'Âge maximal du mot de passe'; Type = 'SecPol'; Key = 'MaximumPasswordAge'; Value = 365; Compare = 'range'; Min = 1; Max = 365 }
        # 1.1.3 : 1 jour minimum entre deux changements, sinon l'historique se contourne en
        # changeant 24 fois de suite.
        @{ Cis = '1.1.3'; Sca = 26002; Title = 'Âge minimal du mot de passe'; Type = 'SecPol'; Key = 'MinimumPasswordAge'; Value = 1; Compare = 'ge' }
        # 1.1.4 : 14 caractères minimum (validé à la main dans le lab, check 26003).
        @{ Cis = '1.1.4'; Sca = 26003; Title = 'Longueur minimale du mot de passe'; Type = 'SecPol'; Key = 'MinimumPasswordLength'; Value = 14; Compare = 'ge' }
        # 1.1.5 : complexité (3 catégories de caractères sur 4). Check SCA non implémenté.
        @{ Cis = '1.1.5'; Sca = $null; Title = 'Complexité du mot de passe'; Type = 'SecPol'; Key = 'PasswordComplexity'; Value = 1; Compare = 'eq' }
        # 1.1.7 : pas de stockage en chiffrement réversible (équivalent clair). Check SCA non implémenté.
        @{ Cis = '1.1.7'; Sca = $null; Title = 'Chiffrement réversible désactivé'; Type = 'SecPol'; Key = 'ClearTextPassword'; Value = 0; Compare = 'eq' }
    )
}
# 1.1.6 « Relax minimum password length limits » (check 26004, registre SAM) n'est pas
# inclus : il ne sert qu'au-delà de 14 caractères. Candidat pour une itération suivante.

if ($Describe) { return $Family }

Import-Module (Join-Path $PSScriptRoot '..\HardeningLib.psm1') -Force
Invoke-HardeningFamily -Family $Family -Apply:$Apply -Rollback:$Rollback -BackupPath $BackupPath `
    -RunDir $RunDir -AcceptLockoutRisk:$AcceptLockoutRisk -Force:$Force
