<?php
/*
 * Réservation DHCP de Kali sur l'interface ATTACK (opt1), pfSense CE 2.9.0. Writeup 05, § 2.6.
 * Adresse hors de la plage dynamique (.100-.199), comme l'exige ISC DHCP pour une réservation.
 * Exécution, depuis l'hôte :
 *   ssh siem-pfsense 'cp /cf/conf/config.xml /cf/conf/config.xml.avant-dhcp-kali && php' < configs/pfsense/dhcp-kali.php
 */
require_once("config.inc");
require_once("services.inc");

$mac = '00:0c:29:89:a5:00';   // carte ethernet0 de la VM Kali (generatedAddress du .vmx)
$ip  = '10.10.20.10';

$maps = config_get_path('dhcpd/opt1/staticmap', []);
foreach ($maps as $m) {
	if (strcasecmp($m['mac'] ?? '', $mac) === 0 || ($m['ipaddr'] ?? '') === $ip) {
		fwrite(STDERR, "Réservation déjà présente : rien n'est modifié.\n");
		exit(1);
	}
}
$maps[] = ['mac' => $mac, 'ipaddr' => $ip, 'hostname' => 'siem-kali', 'descr' => 'Kali (writeup 05)'];
config_set_path('dhcpd/opt1/staticmap', $maps);
write_config('Reservation DHCP Kali (writeup 05) via CLI');
services_dhcpd_configure();
echo "Réservation ajoutée : $mac -> $ip\n";
