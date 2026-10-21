<?php
/*
 * Règles du pare-feu de l'interface ATTACK (opt1), pfSense CE 2.9.0.
 * Writeup 05, § 1.3 et § 2.4. Exécution, depuis l'hôte :
 *   ssh siem-pfsense 'cp /cf/conf/config.xml /cf/conf/config.xml.avant-attack && php' < configs/pfsense/regles-attack.php
 * Idempotent : ne fait rien si ATTACK a déjà des règles (on les gère alors dans l'interface web).
 * Méthode non officielle (API PHP interne de pfSense) : l'interface web reste la voie supportée.
 */
require_once("config.inc");
require_once("filter.inc");

$rules = config_get_path('filter/rule', []);
foreach ($rules as $r) {
	if (($r['interface'] ?? '') === 'opt1') {
		fwrite(STDERR, "ATTACK a déjà des règles : rien n'est modifié.\n");
		exit(1);
	}
}

$src = ['network' => 'opt1'];   // « ATTACK subnets »
$attack = [
	['pass',  'tcp/udp', ['network' => 'opt1ip', 'port' => '53'], false, 'DNS vers pfSense'],
	['pass',  null,      ['address' => '10.10.10.101'],            true,  'Scenarios : Kali vers Windows 11'],
	['block', null,      ['network' => 'lan'],                     true,  'Interdit : LAN (Wazuh, hote)'],
	['block', null,      ['network' => '(self)'],                  true,  'Interdit : administration pfSense'],
	['block', null,      ['network' => 'wan'],                     true,  'Interdit : reseau NAT de l hote'],
	['pass',  'tcp',     ['any' => '', 'port' => '80'],            false, 'Mises a jour Kali (HTTP)'],
	['pass',  'tcp',     ['any' => '', 'port' => '443'],           false, 'Mises a jour Kali (HTTPS)'],
];

$now = time();
foreach ($attack as $i => [$type, $proto, $dst, $log, $descr]) {
	$rule = [
		'type' => $type,
		'interface' => 'opt1',
		'ipprotocol' => 'inet',
		'source' => $src,
		'destination' => $dst,
		'descr' => $descr,
		'tracker' => (string)($now * 100 + $i),
		'created' => ['time' => (string)$now, 'username' => 'CLI regles-attack.php'],
	];
	if ($proto !== null) {
		$rule['protocol'] = $proto;
	}
	if ($log) {
		$rule['log'] = '';
	}
	$rules[] = $rule;
}

config_set_path('filter/rule', $rules);
write_config('Regles ATTACK (writeup 05) via CLI');
$ret = filter_configure();
echo "Règles ATTACK ajoutées : " . count($attack) . ", filter_configure() = " . var_export($ret, true) . "\n";
