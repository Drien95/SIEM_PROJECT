<#
.SYNOPSIS
    Famille 03 : stratégie d'audit avancé (CIS Windows 11 Enterprise v3.0.0, section 17)
    et réglages qui la rendent effective et exploitable par le SOC.

.DESCRIPTION
    Risque : FAIBLE (on ajoute de la journalisation, on n'en retire jamais : un audit déjà
    plus large que le CIS est conservé). Effet attendu : plus d'événements dans le journal
    Security, donc plus de matière pour Wazuh (4688 création de processus avec ligne de
    commande, 4740 verrouillage, 4732 ajout à un groupe, 4719 modification de l'audit…).
    Contrepartie : volume accru ; surveiller le nombre d'événements par seconde côté
    manager (à valider sur le lab).

    Les sous-catégories sont désignées par GUID, pas par nom : sur notre Windows 11 en
    français, « auditpol /get /subcategory:"Logon" » attend le nom traduit. Conséquence
    probable (déduction, à valider) : les checks SCA 26139 à 26165 de la politique Wazuh,
    écrits avec les noms anglais et le motif « Success and Failure », resteront « Failed »
    même une fois l'audit conforme. Le rapport de ce script, qui lit l'état réel par GUID,
    fait alors foi ; voir le README (faux positif SCA lié à la langue).

    GUID : vérifiés le 2026-10-25 contre la liste Microsoft MS-GPAC (voir docs/sources.md).
    Statut : à valider sur la VM.

.EXAMPLE
    .\03-audit-policy.ps1             # dry-run
    .\03-audit-policy.ps1 -Apply      # sauvegarde (auditpol /backup), applique, vérifie
    .\03-audit-policy.ps1 -Rollback   # auditpol /restore de la sauvegarde
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

# Valeurs d'audit : 1 = Succès, 2 = Échec, 3 = Succès et échec. Comparaison « include » :
# les bits attendus doivent être présents, les bits en plus sont gardés.
$S = 1; $F = 2; $SF = 3
$suffix = '-69AE-11D9-BED3-505054503030}'

function New-AuditSetting([string]$Cis, [int]$Sca, [string]$Title, [string]$GuidPrefix, [int]$Bits) {
    @{ Cis = $Cis; Sca = $Sca; Title = $Title; Type = 'AuditPol'; Guid = '{' + $GuidPrefix + $suffix; Value = $Bits; Compare = 'include' }
}

$Family = [ordered]@{
    Id           = '03'
    Name         = 'Stratégie d''audit avancé (CIS 17 + 2.3.2.1, 18.9.3.1, 18.10.25.2.2)'
    Risk         = 'Faible'
    LockoutGuard = $false
    Settings     = @(
        # 2.3.2.1 : sans cette valeur, l'ancienne stratégie d'audit (9 catégories) peut
        # écraser les sous-catégories ci-dessous. Prérequis de toute la famille.
        @{ Cis = '2.3.2.1'; Sca = 26013; Title = 'Forcer les sous-catégories d''audit'; Type = 'Registry'
           Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; ValueType = 'DWord'; Value = 1; Compare = 'eq' }

        # 17.1 Connexion de compte : 4776 validation NTLM (brute force, scénario 1).
        New-AuditSetting '17.1.1' 26139 'Credential Validation' '0CCE923F' $SF
        # 17.2 Gestion des comptes : 4720 création, 4732 ajout à un groupe (persistance).
        New-AuditSetting '17.2.1' 26140 'Application Group Management' '0CCE9239' $SF
        New-AuditSetting '17.2.2' 26141 'Security Group Management' '0CCE9237' $S
        New-AuditSetting '17.2.3' 26142 'User Account Management' '0CCE9235' $SF
        # 17.3 Suivi détaillé : 6416 périphérique PnP, 4688 création de processus.
        New-AuditSetting '17.3.1' 26143 'Plug and Play Events' '0CCE9248' $S
        New-AuditSetting '17.3.2' 26144 'Process Creation' '0CCE922B' $S
        # 17.5 Ouverture/fermeture de session : 4624/4625, 4740 verrouillage, 4672 privilèges.
        New-AuditSetting '17.5.1' 26145 'Account Lockout' '0CCE9217' $F
        New-AuditSetting '17.5.2' 26146 'Group Membership' '0CCE9249' $S
        New-AuditSetting '17.5.3' 26147 'Logoff' '0CCE9216' $S
        New-AuditSetting '17.5.4' 26148 'Logon' '0CCE9215' $SF
        New-AuditSetting '17.5.5' 26149 'Other Logon/Logoff Events' '0CCE921C' $SF
        New-AuditSetting '17.5.6' 26150 'Special Logon' '0CCE921B' $S
        # 17.6 Accès aux objets : partages (5140/5145), stockage amovible, tâches planifiées (4698).
        New-AuditSetting '17.6.1' 26151 'Detailed File Share' '0CCE9244' $F
        New-AuditSetting '17.6.2' 26152 'File Share' '0CCE9224' $SF
        New-AuditSetting '17.6.3' 26153 'Other Object Access Events' '0CCE9227' $SF
        New-AuditSetting '17.6.4' 26154 'Removable Storage' '0CCE9245' $SF
        # 17.7 Changement de stratégie : 4719 audit modifié (anti-forensique), pare-feu.
        New-AuditSetting '17.7.1' 26155 'Audit Policy Change' '0CCE922F' $S
        New-AuditSetting '17.7.2' 26156 'Authentication Policy Change' '0CCE9230' $S
        New-AuditSetting '17.7.3' 26157 'Authorization Policy Change' '0CCE9231' $S
        New-AuditSetting '17.7.4' 26158 'MPSSVC Rule-Level Policy Change' '0CCE9232' $SF
        New-AuditSetting '17.7.5' 26159 'Other Policy Change Events' '0CCE9234' $F
        # 17.8 Utilisation de privilèges sensibles : 4673/4674.
        New-AuditSetting '17.8.1' 26160 'Sensitive Privilege Use' '0CCE9228' $SF
        # 17.9 Système : 4616 heure modifiée (Security State Change), 4697 service installé
        # (Security System Extension, persistance T1543.003).
        New-AuditSetting '17.9.1' 26161 'IPsec Driver' '0CCE9213' $SF
        New-AuditSetting '17.9.2' 26162 'Other System Events' '0CCE9214' $SF
        New-AuditSetting '17.9.3' 26163 'Security State Change' '0CCE9210' $S
        New-AuditSetting '17.9.4' 26164 'Security System Extension' '0CCE9211' $S
        New-AuditSetting '17.9.5' 26165 'System Integrity' '0CCE9212' $SF

        # 18.9.3.1 : ligne de commande dans l'événement 4688. Très utile en chasse (complète
        # Sysmon EID 1). Attention : une ligne de commande peut contenir un mot de passe.
        @{ Cis = '18.9.3.1'; Sca = 26222; Title = 'Ligne de commande dans 4688'; Type = 'Registry'
           Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; ValueType = 'DWord'; Value = 1; Compare = 'eq' }
        # 18.10.25.2.2 : journal Security d'au moins 192 Mo, pour absorber le volume ajouté
        # et ne pas perdre d'événements avant leur collecte par l'agent.
        @{ Cis = '18.10.25.2.2'; Sca = 26376; Title = 'Taille max. du journal Security (Ko)'; Type = 'Registry'
           Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; ValueType = 'DWord'; Value = 196608; Compare = 'ge' }
    )
}

if ($Describe) { return $Family }

Import-Module (Join-Path $PSScriptRoot '..\HardeningLib.psm1') -Force
Invoke-HardeningFamily -Family $Family -Apply:$Apply -Rollback:$Rollback -BackupPath $BackupPath `
    -RunDir $RunDir -AcceptLockoutRisk:$AcceptLockoutRisk -Force:$Force
