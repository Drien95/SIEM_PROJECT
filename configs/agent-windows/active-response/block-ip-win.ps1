# Active Response Wazuh 4.14 pour Windows : bloque une IP source dans le pare-feu Windows.
# À copier dans C:\Program Files (x86)\ossec-agent\active-response\bin\ avec block-ip-win.cmd.
# Fichier enregistré en UTF-8 AVEC BOM : sans BOM, Windows PowerShell 5.1 le lit en ANSI et
# les accents des messages sont cassés.
#
# Pourquoi un script maison : la commande native netsh.exe lit l'IP dans data.srcip, or les
# alertes d'échec de connexion Windows (60122, 60204) la portent dans
# data.win.eventdata.ipAddress (constaté dans notre lab, writeup 07).
#
# Protocole execd (Wazuh >= 4.2) : une ligne JSON sur stdin (command = add ou delete).
# Pour une réponse avec délai (timeout), le script envoie « check_keys » et attend « continue »
# ou « abort » : execd évite ainsi de bloquer deux fois la même IP, puis rappelle le script
# avec « delete » à l'expiration.

$ErrorActionPreference = 'Stop'

# Journal : notre propre fichier, active-response\block-ip-win.log, source de vérité.
# Lancé par wazuh-execd (compte SYSTEM), l'ancien Add-Content vers active-responses.log ne
# laissait aucune ligne alors que la règle pare-feu était créée (writeup 07, § 4.4) : ce fichier
# est aussi écrit par execd. Un fichier dédié évite cette concurrence.
# On garde une copie de la ligne dans active-responses.log quand c'est possible.
# Écriture par .NET en UTF-8 (accents lisibles), ouverte et refermée à chaque ligne.
# Chaque écriture a son try/catch : un échec de journal ne doit jamais empêcher le blocage.
$arDir = Split-Path -Parent $PSScriptRoot
$logFile = Join-Path $arDir 'block-ip-win.log'
$sharedLog = Join-Path $arDir 'active-responses.log'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-ArLog([string]$Message) {
	$stamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
	$line = "$stamp block-ip-win: $Message`r`n"
	try { [System.IO.File]::AppendAllText($logFile, $line, $utf8) } catch { }
	try { [System.IO.File]::AppendAllText($sharedLog, $line, $utf8) } catch { }
}

# Réseaux jamais bloqués : le LAN du lab (hôte, Wazuh, pfSense) et la boucle locale.
function Test-Protected([System.Net.IPAddress]$Address) {
	$b = $Address.GetAddressBytes()
	return ($b[0] -eq 127) -or ($b[0] -eq 10 -and $b[1] -eq 10 -and $b[2] -eq 10)
}

try {
	$message = [Console]::In.ReadLine() | ConvertFrom-Json
	$command = $message.command
	$ipText = $message.parameters.alert.data.win.eventdata.ipAddress

	$address = $null
	if (-not [System.Net.IPAddress]::TryParse([string]$ipText, [ref]$address) -or
		$address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
		Write-ArLog "ignoré : pas d'IPv4 exploitable ('$ipText')"
		exit 0
	}
	$ip = $address.ToString()
	if (Test-Protected $address) {
		Write-ArLog "ignoré : $ip est dans un réseau protégé"
		exit 0
	}
	$ruleName = "Wazuh AR block $ip"

	switch ($command) {
		'add' {
			$check = @{
				version    = 1
				origin     = @{ name = 'block-ip-win'; module = 'active-response' }
				command    = 'check_keys'
				parameters = @{ keys = @($ip) }
			} | ConvertTo-Json -Compress -Depth 5
			[Console]::Out.WriteLine($check)
			[Console]::Out.Flush()
			$answer = [Console]::In.ReadLine() | ConvertFrom-Json
			if ($answer.command -ne 'continue') {
				Write-ArLog "abandon : $ip déjà bloquée"
				exit 0
			}
			New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $ip | Out-Null
			Write-ArLog "ajout : $ip bloquée (règle '$ruleName')"
		}
		'delete' {
			Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
			Write-ArLog "retrait : $ip débloquée"
		}
		default {
			Write-ArLog "ignoré : commande inconnue '$command'"
		}
	}
}
catch {
	Write-ArLog "erreur ($([Environment]::UserName)) : $($_.Exception.Message)"
	exit 1
}
