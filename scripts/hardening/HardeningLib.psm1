#Requires -Version 5.1
<#
.SYNOPSIS
    Bibliothèque commune des scripts de durcissement CIS du lab (agent SIEM-Win11).

.DESCRIPTION
    Fonctions partagées par les familles (families\NN-*.ps1) et l'orchestrateur
    (Invoke-Hardening.ps1) :
      - journalisation horodatée (Write-HardeningLog) ;
      - lecture de l'état réel : politique de sécurité (secedit), stratégie d'audit
        (auditpol), registre ;
      - comparaison à la valeur attendue (Test-HardeningSetting) ;
      - sauvegarde AVANT modification et restauration (New-HardeningBackup,
        Restore-HardeningBackup) ;
      - garde-fou anti-verrouillage (Assert-SafeLockout) ;
      - moteur commun d'une famille (Invoke-HardeningFamily) : dry-run par défaut,
        -Apply pour appliquer, -Rollback pour restaurer.

    Trois types de réglage sont gérés :
      SecPol   : clé de la section [System Access] de secedit (politique de comptes).
      Registry : valeur de registre (HKLM).
      AuditPol : sous-catégorie d'audit avancé, désignée par son GUID (indépendant de la
                 langue de Windows : notre Windows 11 est en français).

    Statut : À VALIDER sur la VM (écrit hors VM, contrôlé uniquement en syntaxe et en
    logique sous PowerShell 7 Linux avec des commandes simulées).

.NOTES
    Wazuh 4.14.9, politique SCA cis_win11_enterprise v3.0.0 (ruleset v4.14.0).
    Sources : voir scripts/hardening/README.md et docs/sources.md.
#>

Set-StrictMode -Version 2.0

# Racine des journaux, rapports et sauvegardes. ProgramData : hors profil utilisateur,
# survit à une fermeture de session, accessible en écriture aux administrateurs.
$script:HardeningRoot = Join-Path $env:ProgramData 'SIEM-Hardening'
$script:LogFile = $null

# Bits de la stratégie d'audit, tels qu'auditpol /backup les écrit dans « Setting Value ».
$script:AuditSuccess = 1
$script:AuditFailure = 2

#region Journalisation et contexte d'exécution

function Initialize-HardeningRun {
    <#
    .SYNOPSIS
        Crée (ou réutilise) le dossier d'une exécution et y ouvre le journal.
    .OUTPUTS
        Chemin du dossier d'exécution (runs\AAAAMMJJ-HHmmss).
    #>
    [CmdletBinding()]
    param([string]$RunDir)

    if (-not $RunDir) {
        $RunDir = Join-Path (Join-Path $script:HardeningRoot 'runs') (Get-Date -Format 'yyyyMMdd-HHmmss')
    }
    if (-not (Test-Path $RunDir)) { New-Item -ItemType Directory -Path $RunDir -Force | Out-Null }
    $script:LogFile = Join-Path $RunDir 'hardening.log'
    return $RunDir
}

function Write-HardeningLog {
    <#
    .SYNOPSIS
        Écrit un message horodaté à l'écran et dans hardening.log du dossier d'exécution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'DRYRUN', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'DRYRUN' { 'Cyan' } 'STEP' { 'Magenta' } default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function Assert-Administrator {
    <# .SYNOPSIS Arrête le script s'il ne tourne pas dans un PowerShell « Exécuter en tant qu'administrateur ». #>
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Ce script doit être lancé depuis un PowerShell ouvert en tant qu''administrateur.'
    }
}

#endregion

#region Lecture de l'état réel

function Get-SecPolSnapshot {
    <#
    .SYNOPSIS
        Exporte la politique de sécurité (secedit) et renvoie la section [System Access]
        sous forme de table clé -> valeur (chaînes).
    .PARAMETER Path
        Si fourni, lit un export existant (sauvegarde) au lieu d'exporter.
    #>
    [CmdletBinding()]
    param([string]$Path)

    $temp = $null
    if (-not $Path) {
        $temp = Join-Path $env:TEMP ('secpol-{0}.inf' -f [guid]::NewGuid())
        & secedit.exe /export /cfg $temp /areas SECURITYPOLICY /quiet | Out-Null
        if (-not (Test-Path $temp)) { throw 'secedit /export n''a produit aucun fichier.' }
        $Path = $temp
    }
    $values = @{}
    $section = ''
    foreach ($line in Get-Content -Path $Path) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
        if ($section -eq 'System Access' -and $line -match '^\s*(\w+)\s*=\s*(.*?)\s*$') {
            $values[$Matches[1]] = $Matches[2]
        }
    }
    if ($temp) { Remove-Item $temp -Force -ErrorAction SilentlyContinue }
    return $values
}

function Get-AuditPolSnapshot {
    <#
    .SYNOPSIS
        Renvoie la stratégie d'audit avancé : table GUID de sous-catégorie -> bits
        (0 aucun, 1 succès, 2 échec, 3 les deux).
    .DESCRIPTION
        On passe par « auditpol /backup » (CSV) plutôt que « auditpol /get » : la colonne
        « Setting Value » est numérique et le GUID ne dépend pas de la langue, alors que
        /get affiche « Succès et échec » sur un Windows français.
    .PARAMETER Path
        Si fourni, lit un CSV de sauvegarde existant au lieu d'en créer un.
    #>
    [CmdletBinding()]
    param([string]$Path)

    $temp = $null
    if (-not $Path) {
        $temp = Join-Path $env:TEMP ('auditpol-{0}.csv' -f [guid]::NewGuid())
        & auditpol.exe /backup "/file:$temp" | Out-Null
        if (-not (Test-Path $temp)) { throw 'auditpol /backup n''a produit aucun fichier.' }
        $Path = $temp
    }
    # Colonnes : Machine Name, Policy Target, Subcategory, Subcategory GUID,
    # Inclusion Setting, Exclusion Setting, Setting Value. On lit par position pour
    # ne pas dépendre de l'intitulé des en-têtes.
    $header = 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value'
    $rows = Get-Content -Path $Path | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header
    $values = @{}
    foreach ($row in $rows) {
        if ($row.Guid -match '^\{[0-9A-Fa-f-]{36}\}$' -and $row.Value -match '^\d+$') {
            $values[$row.Guid.ToUpperInvariant()] = [int]$row.Value
        }
    }
    if ($temp) { Remove-Item $temp -Force -ErrorAction SilentlyContinue }
    return $values
}

function Get-RegistrySetting {
    <# .SYNOPSIS Lit une valeur de registre ; renvoie Exists, Value et Kind (type). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)

    $result = [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    if (Test-Path $Path) {
        $key = Get-Item -Path $Path
        if ($key.GetValueNames() -contains $Name) {
            $result.Exists = $true
            $result.Value = $key.GetValue($Name)
            $result.Kind = $key.GetValueKind($Name).ToString()
        }
    }
    return $result
}

function Get-HardeningState {
    <#
    .SYNOPSIS
        Photographie de l'état réel nécessaire pour tester une liste de réglages
        (un seul export secedit et un seul auditpol /backup par passe).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Settings)

    $types = $Settings | ForEach-Object { $_.Type } | Sort-Object -Unique
    $state = @{ SecPol = @{}; AuditPol = @{}; Registry = @{} }
    if ($types -contains 'SecPol') { $state.SecPol = Get-SecPolSnapshot }
    if ($types -contains 'AuditPol') { $state.AuditPol = Get-AuditPolSnapshot }
    foreach ($s in @($Settings | Where-Object { $_.Type -eq 'Registry' })) {
        $state.Registry["$($s.Path)\$($s.Name)"] = Get-RegistrySetting -Path $s.Path -Name $s.Name
    }
    return $state
}

#endregion

#region Comparaison

function Get-SettingActual {
    <# .SYNOPSIS Valeur d'un réglage telle que lue dans la photographie $State. #>
    param([Parameter(Mandatory)][hashtable]$Setting, [Parameter(Mandatory)][hashtable]$State)

    switch ($Setting.Type) {
        'SecPol' {
            if ($State.SecPol.ContainsKey($Setting.Key)) { return [int]$State.SecPol[$Setting.Key] }
            return $null
        }
        'AuditPol' {
            $guid = $Setting.Guid.ToUpperInvariant()
            # Sous-catégorie absente du CSV = jamais configurée = aucun audit (0).
            if ($State.AuditPol.ContainsKey($guid)) { return $State.AuditPol[$guid] }
            return 0
        }
        'Registry' {
            $reg = $null
            if ($State.ContainsKey('Registry')) { $reg = $State.Registry["$($Setting.Path)\$($Setting.Name)"] }
            if (-not $reg) { $reg = Get-RegistrySetting -Path $Setting.Path -Name $Setting.Name }
            if ($reg.Exists) { return $reg.Value }
            return $null
        }
        default { throw "Type de réglage inconnu : $($Setting.Type)" }
    }
}

function Format-SettingValue {
    <# .SYNOPSIS Texte lisible d'une valeur (bits d'audit traduits en Succès/Échec). #>
    param([hashtable]$Setting, $Value)

    if ($null -eq $Value) { return '(non défini)' }
    if ($Setting.Type -eq 'AuditPol') {
        switch ([int]$Value) { 0 { return 'Aucun' } 1 { return 'Succès' } 2 { return 'Échec' } 3 { return 'Succès et échec' } }
    }
    return [string]$Value
}

function Format-SettingExpected {
    <# .SYNOPSIS Texte lisible de la valeur attendue selon l'opérateur de comparaison. #>
    param([hashtable]$Setting)

    $value = Format-SettingValue -Setting $Setting -Value $Setting.Value
    switch ($Setting.Compare) {
        'eq' { return "= $value" }
        'ge' { return ">= $value" }
        'le' { return "<= $value" }
        'range' { return "$($Setting.Min)..$($Setting.Max)" }
        'include' { return "inclut $value" }
    }
}

function Test-SettingValue {
    <#
    .SYNOPSIS
        Compare une valeur à l'attendu du réglage.
    .DESCRIPTION
        Opérateurs (champ Compare du réglage) :
          eq      égalité stricte ;
          ge / le supérieur ou égal / inférieur ou égal (comme le SCA : compare >= 14) ;
          range   entre Min et Max inclus (ex. âge maximal 1..365 : « 365 ou moins, mais pas 0 ») ;
          include tous les bits attendus présents (audit « inclut Succès »).
    #>
    param([Parameter(Mandatory)][hashtable]$Setting, $Actual)

    if ($null -eq $Actual) { return $false }
    switch ($Setting.Compare) {
        'eq' { return ([string]$Actual -eq [string]$Setting.Value) }
        'ge' { return ([int]$Actual -ge [int]$Setting.Value) }
        'le' { return ([int]$Actual -le [int]$Setting.Value) }
        'range' { return ([int]$Actual -ge [int]$Setting.Min -and [int]$Actual -le [int]$Setting.Max) }
        'include' { return (([int]$Actual -band [int]$Setting.Value) -eq [int]$Setting.Value) }
        default { throw "Opérateur de comparaison inconnu : $($Setting.Compare)" }
    }
}

function Test-HardeningSetting {
    <#
    .SYNOPSIS
        Relit la valeur appliquée d'un réglage et la compare à l'attendu.
    .OUTPUTS
        Objet { Actual, Compliant }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Setting, [hashtable]$State)

    if (-not $State) { $State = Get-HardeningState -Settings @($Setting) }
    $actual = Get-SettingActual -Setting $Setting -State $State
    return [pscustomobject]@{ Actual = $actual; Compliant = (Test-SettingValue -Setting $Setting -Actual $actual) }
}

#endregion

#region Application

function Get-SettingTarget {
    <#
    .SYNOPSIS
        Valeur à écrire pour rendre un réglage conforme.
    .DESCRIPTION
        Pour l'audit (« include »), on AJOUTE les bits attendus aux bits existants : on ne
        réduit jamais un audit déjà plus large que le CIS.
    #>
    param([Parameter(Mandatory)][hashtable]$Setting, $Actual)

    if ($Setting.Compare -eq 'include') {
        $current = 0
        if ($null -ne $Actual) { $current = [int]$Actual }
        return ($current -bor [int]$Setting.Value)
    }
    return $Setting.Value
}

function Set-SecPolValues {
    <#
    .SYNOPSIS
        Applique des clés [System Access] via un modèle secedit temporaire.
    .PARAMETER Values
        Table ordonnée clé -> valeur. L'ordre compte : pour le verrouillage, le seuil
        (LockoutBadCount) doit précéder la durée et la réinitialisation.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    $stamp = [guid]::NewGuid()
    $inf = Join-Path $env:TEMP "hardening-$stamp.inf"
    $db = Join-Path $env:TEMP "hardening-$stamp.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
    foreach ($k in $Values.Keys) { $lines += ('{0} = {1}' -f $k, $Values[$k]) }
    # Signature littérale « $CHICAGO$ » (chaîne entre apostrophes : pas d'expansion).
    $lines += '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
    # secedit attend un modèle en UTF-16 LE (« Unicode » pour PowerShell 5.1).
    $lines | Out-File -FilePath $inf -Encoding Unicode
    & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
    $code = $LASTEXITCODE
    Remove-Item $inf, $db, ($db -replace '\.sdb$', '.jfm') -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        # La vérité reste la relecture (Test-HardeningSetting) : secedit peut renvoyer un
        # code non nul pour un simple avertissement (voir %windir%\security\logs\scesrv.log).
        Write-HardeningLog -Level WARN -Message "secedit /configure a renvoyé le code $code (détail : $env:windir\security\logs\scesrv.log)."
    }
}

function Set-AuditPolValue {
    <# .SYNOPSIS Active succès et/ou échec d'une sous-catégorie d'audit (par GUID). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Guid, [Parameter(Mandatory)][int]$Bits)

    $success = if ($Bits -band $script:AuditSuccess) { 'enable' } else { 'disable' }
    $failure = if ($Bits -band $script:AuditFailure) { 'enable' } else { 'disable' }
    $output = (& auditpol.exe /set "/subcategory:$Guid" "/success:$success" "/failure:$failure") | Out-String
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set $Guid a échoué : $output" }
}

function Set-RegistrySetting {
    <# .SYNOPSIS Écrit une valeur de registre (crée la clé si besoin). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value, [string]$Kind = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
}

#endregion

#region Sauvegarde et restauration

function New-HardeningBackup {
    <#
    .SYNOPSIS
        Sauvegarde, AVANT toute modification, tout ce qu'une famille peut toucher.
    .DESCRIPTION
        Dossier <RunDir>\backups\<Id famille>\ :
          secpol.inf    export complet secedit (SECURITYPOLICY) ;
          auditpol.csv  stratégie d'audit complète (auditpol /backup) ;
          registry.json valeurs de registre de la famille (existence, valeur, type) ;
          manifest.json famille, machine, date, liste des réglages, état Applied.
        Aucun secret : secedit ne contient pas de hash de mot de passe.
    .OUTPUTS
        Chemin du dossier de sauvegarde.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Family, [Parameter(Mandatory)][string]$RunDir)

    $dir = Join-Path (Join-Path $RunDir 'backups') $Family.Id
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    & secedit.exe /export /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY /quiet | Out-Null
    & auditpol.exe /backup "/file:$(Join-Path $dir 'auditpol.csv')" | Out-Null

    $registry = @()
    foreach ($s in @($Family.Settings | Where-Object { $_.Type -eq 'Registry' })) {
        $reg = Get-RegistrySetting -Path $s.Path -Name $s.Name
        $registry += [pscustomobject]@{ Path = $s.Path; Name = $s.Name; Exists = $reg.Exists; Value = $reg.Value; Kind = $reg.Kind }
    }
    ConvertTo-Json -InputObject @($registry) -Depth 4 | Set-Content -Path (Join-Path $dir 'registry.json') -Encoding UTF8

    foreach ($f in 'secpol.inf', 'auditpol.csv') {
        if (-not (Test-Path (Join-Path $dir $f))) { throw "Sauvegarde incomplète : $f absent de $dir. Arrêt, rien n'a été modifié." }
    }

    $manifest = [pscustomobject]@{
        Family   = $Family.Id
        Name     = $Family.Name
        Computer = $env:COMPUTERNAME
        Created  = (Get-Date).ToString('s')
        Applied  = $false
        Settings = @($Family.Settings | ForEach-Object { $_.Cis })
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $dir 'manifest.json') -Encoding UTF8
    Write-HardeningLog -Level OK -Message "Sauvegarde créée : $dir"
    return $dir
}

function Set-BackupApplied {
    <# .SYNOPSIS Marque une sauvegarde comme « appliquée » (sert à retrouver la dernière pour -Rollback). #>
    param([Parameter(Mandatory)][string]$BackupPath)
    $file = Join-Path $BackupPath 'manifest.json'
    $manifest = Get-Content $file -Raw | ConvertFrom-Json
    $manifest.Applied = $true
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $file -Encoding UTF8
}

function Find-LatestBackup {
    <# .SYNOPSIS Dernière sauvegarde appliquée d'une famille, toutes exécutions confondues. #>
    param([Parameter(Mandatory)][string]$FamilyId)

    $runs = Join-Path $script:HardeningRoot 'runs'
    if (-not (Test-Path $runs)) { return $null }
    $candidates = Get-ChildItem -Path $runs -Directory | Sort-Object Name -Descending
    foreach ($run in $candidates) {
        $dir = Join-Path (Join-Path $run.FullName 'backups') $FamilyId
        $file = Join-Path $dir 'manifest.json'
        if ((Test-Path $file) -and (Get-Content $file -Raw | ConvertFrom-Json).Applied) { return $dir }
    }
    return $null
}

function Restore-HardeningBackup {
    <#
    .SYNOPSIS
        Remet les réglages d'une famille dans l'état de la sauvegarde.
    .DESCRIPTION
        SecPol   : réécrit uniquement les clés de la famille, avec leur valeur sauvegardée
                   (les autres clés de la politique ne sont pas touchées).
        AuditPol : auditpol /restore du CSV complet sauvegardé.
        Registry : remet la valeur d'origine, ou supprime la valeur si elle n'existait pas.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Family, [Parameter(Mandatory)][string]$BackupPath)

    if (-not (Test-Path (Join-Path $BackupPath 'manifest.json'))) { throw "Sauvegarde introuvable ou invalide : $BackupPath" }
    $settings = @($Family.Settings)

    $secKeys = @($settings | Where-Object { $_.Type -eq 'SecPol' } | ForEach-Object { $_.Key })
    if ($secKeys.Count -gt 0) {
        $saved = Get-SecPolSnapshot -Path (Join-Path $BackupPath 'secpol.inf')
        $restore = [ordered]@{}
        foreach ($k in $secKeys) {
            if ($saved.ContainsKey($k)) { $restore[$k] = $saved[$k] }
            else { Write-HardeningLog -Level WARN -Message "$k n'était pas défini dans la sauvegarde : laissé tel quel." }
        }
        # Seuil de verrouillage remis à 0 = verrouillage désactivé : la durée et la remise à
        # zéro n'ont alors plus de sens et secedit peut les refuser. On n'écrit que le seuil.
        if ($restore.Contains('LockoutBadCount') -and [int]$restore['LockoutBadCount'] -eq 0) {
            foreach ($k in 'LockoutDuration', 'ResetLockoutCount') { if ($restore.Contains($k)) { $restore.Remove($k) } }
        }
        if ($restore.Count -gt 0) {
            Set-SecPolValues -Values $restore
            Write-HardeningLog -Level OK -Message ('Politique restaurée : ' + (($restore.Keys | ForEach-Object { "$_=$($restore[$_])" }) -join ', '))
        }
    }

    if (@($settings | Where-Object { $_.Type -eq 'AuditPol' }).Count -gt 0) {
        $output = (& auditpol.exe /restore "/file:$(Join-Path $BackupPath 'auditpol.csv')") | Out-String
        if ($LASTEXITCODE -ne 0) { throw "auditpol /restore a échoué : $output" }
        Write-HardeningLog -Level OK -Message 'Stratégie d''audit restaurée depuis auditpol.csv.'
    }

    $regFile = Join-Path $BackupPath 'registry.json'
    if (Test-Path $regFile) {
        # Windows PowerShell 5.1 : ConvertFrom-Json émet un tableau JSON comme UN seul objet
        # (pas d'énumération). @(... | ConvertFrom-Json) donnait donc un tableau contenant le
        # tableau : pour une famille sans registre (« [] »), $r était un tableau vide et
        # $r.Exists levait PropertyNotFoundStrict (StrictMode 2.0). On passe par une variable
        # pour itérer sur les éléments eux-mêmes (même résultat sous PowerShell 7).
        $savedRegistry = Get-Content $regFile -Raw | ConvertFrom-Json
        foreach ($r in @($savedRegistry)) {
            if ($null -eq $r -or -not $r.PSObject.Properties['Exists']) { continue }
            if ($r.Exists) {
                Set-RegistrySetting -Path $r.Path -Name $r.Name -Value $r.Value -Kind $r.Kind
                Write-HardeningLog -Level OK -Message "Registre restauré : $($r.Path)\$($r.Name) = $($r.Value)"
            }
            elseif ((Get-RegistrySetting -Path $r.Path -Name $r.Name).Exists) {
                Remove-ItemProperty -Path $r.Path -Name $r.Name -Force
                Write-HardeningLog -Level OK -Message "Registre : $($r.Path)\$($r.Name) supprimé (absent avant durcissement)."
            }
        }
    }
}

#endregion

#region Garde-fou anti-verrouillage

function Get-LocalAdminAccounts {
    <#
    .SYNOPSIS
        Comptes LOCAUX activés membres du groupe Administrateurs.
    .DESCRIPTION
        Groupe désigné par son SID S-1-5-32-544 (son nom est traduit : « Administrateurs »
        sur notre Windows français). Les membres de domaine ou Microsoft Entra sont ignorés.
    #>
    $members = @()
    try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop) }
    catch {
        # Get-LocalGroupMember échoue s'il reste un SID orphelin dans le groupe : repli WMI.
        Write-HardeningLog -Level WARN -Message "Get-LocalGroupMember a échoué ($($_.Exception.Message)) : repli sur WMI."
        $group = Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'"
        $users = Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_UserAccount
        return @($users | Where-Object { $_.LocalAccount -and -not $_.Disabled } | ForEach-Object { $_.Name })
    }
    $names = @()
    foreach ($m in $members) {
        # Un groupe ou un compte de domaine n'est pas un utilisateur local : Get-LocalUser ne
        # le trouve pas (plus sûr que ObjectClass, dont le libellé est traduit).
        $local = Get-LocalUser -SID $m.SID -ErrorAction SilentlyContinue
        if ($local -and $local.Enabled) { $names += $local.Name }
    }
    return $names
}

function Assert-SafeLockout {
    <#
    .SYNOPSIS
        Refuse d'activer un verrouillage de compte sans filet de sécurité.
    .DESCRIPTION
        Conditions, toutes obligatoires :
          1. le switch -AcceptLockoutRisk est passé (choix explicite) ;
          2. au moins DEUX comptes locaux administrateurs activés : si l'un est verrouillé,
             l'autre (le compte « de secours ») permet de le déverrouiller ;
          3. la procédure de déverrouillage est affichée AVANT l'application ;
          4. confirmation tapée « OUI », sauf -Force (mode automatisé).
    #>
    [CmdletBinding()]
    param([switch]$AcceptLockoutRisk, [switch]$Force, [int]$MinimumAdmins = 2)

    if (-not $AcceptLockoutRisk) {
        throw ('Famille à risque de verrouillage : relancer avec -AcceptLockoutRisk après avoir lu ' +
            'scripts\hardening\README.md (section « Verrouillage de comptes »). Rien n''a été modifié.')
    }

    $admins = @(Get-LocalAdminAccounts)
    Write-HardeningLog -Message ("Administrateurs locaux activés : {0}" -f ($admins -join ', '))
    if ($admins.Count -lt $MinimumAdmins) {
        throw ("Il faut au moins $MinimumAdmins comptes administrateurs locaux activés (compte de secours). " +
            'Créer le compte de secours décrit dans le README puis relancer. Rien n''a été modifié.')
    }

    $unlock = @'
================ AVANT D'APPLIQUER : PROCÉDURE DE DÉVERROUILLAGE ================
Si un compte est verrouillé, ouvrir une session avec un AUTRE administrateur
(le compte de secours), puis dans un PowerShell administrateur :

    net user analyste /active:yes        # réactive le compte (remplacer analyste si besoin)
    net accounts /lockoutthreshold:0     # désactive le verrouillage (retour lab)

Ou restaurer l'état d'avant durcissement :

    .\Invoke-Hardening.ps1 -Rollback -Families 02

Sans rien faire, un compte verrouillé se débloque seul après la durée de
verrouillage (15 minutes avec ce script).
=================================================================================
'@
    Write-Host $unlock -ForegroundColor Yellow
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $unlock -Encoding UTF8 }

    if (-not $Force) {
        $answer = Read-Host 'Tapez OUI (en majuscules) pour appliquer le verrouillage de comptes'
        if ($answer -cne 'OUI') { throw 'Confirmation refusée : rien n''a été modifié.' }
    }
}

#endregion

#region Moteur d'une famille

function New-HardeningResult {
    param([System.Collections.IDictionary]$Family, [hashtable]$Setting, $Before, $After, [string]$Action, [string]$Status)
    [pscustomobject]@{
        Famille = $Family.Id
        CIS     = $Setting.Cis
        SCA     = $(if ($Setting.Sca) { $Setting.Sca } else { '-' })
        Reglage = $Setting.Title
        Attendu = Format-SettingExpected -Setting $Setting
        Avant   = Format-SettingValue -Setting $Setting -Value $Before
        Apres   = Format-SettingValue -Setting $Setting -Value $After
        Action  = $Action
        Statut  = $Status
    }
}

function Invoke-HardeningFamily {
    <#
    .SYNOPSIS
        Exécute une famille : dry-run (défaut), application (-Apply) ou restauration (-Rollback).
    .DESCRIPTION
        Dry-run   : lit l'état réel, affiche ce qui serait changé. Ne modifie rien,
                    ne sauvegarde rien.
        -Apply    : garde-fou éventuel -> sauvegarde -> application des seuls réglages non
                    conformes (idempotent) -> relecture et verdict PASS / FAIL par réglage.
        -Rollback : restaure la sauvegarde indiquée (-BackupPath) ou la dernière appliquée,
                    puis relit l'état.
    .OUTPUTS
        Un objet résultat par réglage (pour le rapport de l'orchestrateur).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Family,
        [switch]$Apply, [switch]$Rollback, [string]$BackupPath, [string]$RunDir,
        [switch]$AcceptLockoutRisk, [switch]$Force
    )

    Assert-Administrator
    $RunDir = Initialize-HardeningRun -RunDir $RunDir
    $settings = @($Family.Settings)
    $mode = if ($Rollback) { 'ROLLBACK' } elseif ($Apply) { 'APPLY' } else { 'DRY-RUN' }
    Write-HardeningLog -Level STEP -Message "Famille $($Family.Id) - $($Family.Name) [$mode] (risque : $($Family.Risk))"

    $before = Get-HardeningState -Settings $settings

    if ($Rollback) {
        if (-not $BackupPath) { $BackupPath = Find-LatestBackup -FamilyId $Family.Id }
        if (-not $BackupPath) { throw "Aucune sauvegarde appliquée trouvée pour la famille $($Family.Id)." }
        Write-HardeningLog -Message "Restauration depuis $BackupPath"
        Restore-HardeningBackup -Family $Family -BackupPath $BackupPath
        $after = Get-HardeningState -Settings $settings
        foreach ($s in $settings) {
            New-HardeningResult -Family $Family -Setting $s -Before (Get-SettingActual $s $before) `
                -After (Get-SettingActual $s $after) -Action 'Restauré' -Status 'ROLLBACK'
        }
        return
    }

    # Réglages déjà conformes : rien à faire (idempotence).
    $todo = @()
    foreach ($s in $settings) {
        $actual = Get-SettingActual -Setting $s -State $before
        if (Test-SettingValue -Setting $s -Actual $actual) {
            Write-HardeningLog -Level OK -Message ("[{0}] {1} : conforme ({2})" -f $s.Cis, $s.Title, (Format-SettingValue $s $actual))
        }
        else {
            $level = if ($Apply) { 'INFO' } else { 'DRYRUN' }
            Write-HardeningLog -Level $level -Message ("[{0}] {1} : {2} -> {3}" -f $s.Cis, $s.Title,
                (Format-SettingValue $s $actual), (Format-SettingValue $s (Get-SettingTarget $s $actual)))
            $todo += $s
        }
    }

    if (-not $Apply) {
        foreach ($s in $settings) {
            $actual = Get-SettingActual -Setting $s -State $before
            $ok = Test-SettingValue -Setting $s -Actual $actual
            New-HardeningResult -Family $Family -Setting $s -Before $actual -After $actual `
                -Action $(if ($ok) { 'Conforme' } else { 'À modifier' }) -Status $(if ($ok) { 'PASS' } else { 'DRYRUN' })
        }
        Write-HardeningLog -Level DRYRUN -Message "$($todo.Count) réglage(s) à modifier. Rien n'a été appliqué (ajouter -Apply)."
        return
    }

    if ($todo.Count -gt 0) {
        if ($Family.LockoutGuard) { Assert-SafeLockout -AcceptLockoutRisk:$AcceptLockoutRisk -Force:$Force }
        $backup = New-HardeningBackup -Family $Family -RunDir $RunDir

        $secValues = [ordered]@{}
        foreach ($s in $todo) {
            $target = Get-SettingTarget -Setting $s -Actual (Get-SettingActual -Setting $s -State $before)
            try {
                switch ($s.Type) {
                    'SecPol' { $secValues[$s.Key] = $target }
                    'AuditPol' { Set-AuditPolValue -Guid $s.Guid -Bits $target }
                    'Registry' { Set-RegistrySetting -Path $s.Path -Name $s.Name -Value $target -Kind $s.ValueType }
                }
            }
            catch { Write-HardeningLog -Level ERROR -Message "[$($s.Cis)] $($s.Title) : $($_.Exception.Message)" }
        }
        if ($secValues.Count -gt 0) { Set-SecPolValues -Values $secValues }
        Set-BackupApplied -BackupPath $backup
        Write-HardeningLog -Message "Rollback possible : -Rollback -BackupPath `"$backup`""
    }

    # Vérification : on relit l'état réel, on ne fait pas confiance aux codes de retour.
    $after = Get-HardeningState -Settings $settings
    foreach ($s in $settings) {
        $b = Get-SettingActual -Setting $s -State $before
        $a = Get-SettingActual -Setting $s -State $after
        $ok = Test-SettingValue -Setting $s -Actual $a
        $action = if ($todo -contains $s) { 'Modifié' } else { 'Conforme' }
        if ($ok) { Write-HardeningLog -Level OK -Message "[$($s.Cis)] $($s.Title) : PASS ($(Format-SettingValue $s $a))" }
        else { Write-HardeningLog -Level ERROR -Message "[$($s.Cis)] $($s.Title) : FAIL (lu : $(Format-SettingValue $s $a), attendu $(Format-SettingExpected $s))" }
        New-HardeningResult -Family $Family -Setting $s -Before $b -After $a -Action $action -Status $(if ($ok) { 'PASS' } else { 'FAIL' })
    }
}

#endregion

Export-ModuleMember -Function Initialize-HardeningRun, Write-HardeningLog, Assert-Administrator,
    Get-SecPolSnapshot, Get-AuditPolSnapshot, Get-RegistrySetting, Get-HardeningState,
    Test-HardeningSetting, Test-SettingValue, Get-SettingActual, Get-SettingTarget,
    New-HardeningBackup, Restore-HardeningBackup, Find-LatestBackup,
    Get-LocalAdminAccounts, Assert-SafeLockout, Invoke-HardeningFamily
