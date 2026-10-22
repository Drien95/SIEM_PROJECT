# Active Response Wazuh 4.14 pour Windows : bloque une IP source dans le pare-feu Windows.
# À copier dans C:\Program Files (x86)\ossec-agent\active-response\bin\ avec block-ip-win.cmd.
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
$logFile = Join-Path $PSScriptRoot '..\active-responses.log'

function Write-ArLog([string]$Message) {
	$stamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
	Add-Content -Path $logFile -Value "$stamp block-ip-win: $Message"
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
	Write-ArLog "erreur : $($_.Exception.Message)"
	exit 1
}
