# Sources

Consultées le 2026-10-20. Le contenu externe est du matériel de référence, à vérifier
avant usage.

## Documentation officielle Wazuh

https://documentation.wazuh.com/current/index.html — branche **4.x** (script
d'installation en 4.14).

Pages utiles :

- Quickstart : `quickstart.html`
- Architecture et ports : `getting-started/architecture.html`
- Guide d'installation : `installation-guide/index.html`
- Options de déploiement (OVA, Docker, Kubernetes, Ansible) : `deployment-options/index.html`
- Capacités : `user-manual/capabilities/index.html`
- Guide de preuve de concept (scénarios de détection prêts à l'emploi) : `proof-of-concept-guide/index.html`
- Conformité (PCI DSS, GDPR, HIPAA, NIST 800-53) : `compliance/index.html`

## marxgoo/Wazuh-SOC-Lab

https://github.com/marxgoo/Wazuh-SOC-Lab

- **Apport** : lab SOC complet sous VMware (Wazuh OVA, Windows 11 + Sysmon, Kali,
  pfSense, Suricata) ; intégrations VirusTotal, FIM, pfSense, Suricata ; scénario de
  brute force SSH avec Hydra.
- **Limites** : pas de version Wazuh ni de mapping MITRE ; plusieurs erreurs de chemins et
  de services dans les PDF. Notes de lecture et corrections : [lab-marxgoo.md](lab-marxgoo.md).

## UsmanPrime/Wazuh-Setup

https://github.com/UsmanPrime/Wazuh-Setup

- **Apport** : guide pas à pas pour machine modeste (4-8 Go) : réglages mémoire et délai
  de l'indexeur, ports, agents Windows/Linux, FIM, Defender + EICAR, Sysmon, règle
  personnalisée `local_rules.xml`, tableau de dépannage.
- **Limites** : uniquement l'OVA ; certaines explications (bruit Sysmon de bas niveau)
  sont celles de l'auteur, non vérifiées.

## SSH et images

- Clé « insecure » de Vagrant, publique (constat du writeup 03, § 2.3 bis) :
  https://github.com/hashicorp/vagrant/tree/main/keys
- Accès SSH à pfSense : https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html

## Réseau (simulateur de paquets)

Utilisées par l'[annexe simulateur](writeup/annexe-simulateur-paquets.md) :

- RFC 826 (ARP), RFC 2131 (DHCP), RFC 3927 (APIPA), RFC 5424 (syslog), RFC 5737 (adresses de
  documentation) : https://www.rfc-editor.org/
- NAT sortant et pare-feu à états pfSense :
  https://docs.netgate.com/pfsense/en/latest/nat/outbound.html,
  https://docs.netgate.com/pfsense/en/latest/firewall/fundamentals.html
- Enrôlement des agents Wazuh :
  https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html

## Scénario brute force SMB

Utilisées par la [fiche brute force SMB](scenarios/brute-force-smb.md) et le
[writeup 06](writeup/06-scenario-brute-force-smb.md) :

- Événement 4625, champs `status` / `subStatus` (0xC000006A, 0xC0000064) :
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Règles 60105, 60122, 60204 et variable `MS_FREQ` (ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0580-win-security_rules.xml
- MITRE ATT&CK T1110 (Brute Force) et T1531 (Account Access Removal) :
  https://attack.mitre.org/techniques/T1110/, https://attack.mitre.org/techniques/T1531/

## Règles et réponse active

Utilisées par le [writeup 07](writeup/07-regles-et-reponse-active.md) :

- Réponse active : https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html,
  https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html,
  https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html
- Syntaxe des règles : https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- `wazuh-logtest` : https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
- `New-NetFirewallRule` : https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule

## Scénario Suricata sur pfSense

Utilisées par la [fiche Suricata](scenarios/suricata-nids.md), le
[writeup 10](writeup/10-scenario-suricata-nids.md) et l'[intégration](integrations/suricata.md) :

- Règles natives Suricata 86600-86604 (vérifiées, ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0475-suricata_rules.xml
- Décodeur natif `json` (`<prematch>^{\s*"</prematch>`, vérifié) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/decoders/0006-json_decoders.xml
- Plugin `JSON_Decoder` et motif `offset="after_prematch"` :
  https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
- Syntaxe des décodeurs (OS_Regex, `parent`, `plugin_decoder`, offsets) :
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html,
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html
- Syntaxe des règles (`if_sid`, `field type="pcre2"`) :
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- Lecture d'un fichier JSON (`log_format json`, option B) :
  https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Sortie EVE JSON de Suricata : https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Variables `HOME_NET` / `EXTERNAL_NET` : https://docs.suricata.io/en/latest/configuration/suricata-yaml.html
- Paquet Suricata de pfSense : https://docs.netgate.com/pfsense/en/latest/packages/suricata/index.html
- Ruleset ET Open (Proofpoint Emerging Threats) : https://rules.emergingthreats.net/
- Syslog RFC 5424 (en-tête, MSGID et données structurées « - ») : https://www.rfc-editor.org/rfc/rfc5424
- rsyslog (option B, à valider) : https://www.rsyslog.com/doc/configuration/index.html

## Scénario 5 : Sysmon et LSASS

Utilisées par le [writeup 15](writeup/15-detection-acces-identifiants-lsass.md) (en cours, à rédiger par l'auteur).

Références pour la configuration [`sysmon-lab.xml`](../configs/agent-windows/sysmon-lab.xml) et la
règle locale 100220 (fiche à venir) :

- Sysmon (événement 10, conditions de filtre, option `-c`) :
  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Règle native Sysmon EID 10 **61612** (niveau 0, vérifiée, ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0595-win-sysmon_rules.xml
- Règle native **92900** (niveau 12, T1003.001 ; masques `0x1010` et `0x40`, exclut
  `C:\Program Files` et `wmiprvse.exe` ; vérifiée, ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0945-sysmon_id_10.xml
- Protection LSA (RunAsPPL, événement WinInit 12) :
  https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- Droits d'accès aux processus : https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
- MITRE ATT&CK T1003.001 : https://attack.mitre.org/techniques/T1003/001/
- CVE-2022-26925 (Windows LSA Spoofing, catalogue KEV de la CISA) : https://nvd.nist.gov/vuln/detail/CVE-2022-26925
- CVE-2021-36934 (HiveNightmare) : https://www.malwarebytes.com/blog/news/2021/07/hivenightmare-zero-day-lets-anyone-be-system-on-windows-10-and-11
- Fin de PPLdump (correctif de juillet 2022, sans CVE) : https://itm4n.github.io/the-end-of-ppldump/
- PPLFault (non corrigé par Microsoft, sans CVE) : https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need

## Scénario 5b : persistance par clé Run

Utilisées par la [fiche clé Run](scenarios/persistance-run-key.md) et le
[writeup 11](writeup/11-scenario-persistance-run-key.md) :

- MITRE ATT&CK T1547.001 : https://attack.mitre.org/techniques/T1547/001/
- Clés Run et RunOnce : https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
- Règles natives 92300-92303 (vérifiées, ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0860-sysmon_id_13.xml
- Règles 60004, 61600, 61615 (vérifiées) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0575-win-base_rules.xml,
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0595-win-sysmon_rules.xml
- Archivage de tous les événements (`logall_json`) :
  https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html

## SCA et CIS

Utilisées par l'[intégration SCA](integrations/sca.md) et le [writeup 12](writeup/12-sca-cis-windows11.md) :

- SCA, présentation et fonctionnement :
  https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html,
  https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html
- Conditions `all` / `any` / `none`, résultat « Not applicable » :
  https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html
- Bloc `<sca>` et valeurs par défaut : https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/sca.html
- Politique CIS Windows 11 Enterprise v3.0.0, check 26003 (vérifiée, 482 checks, ruleset v4.14.0) :
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/sca/windows/cis_win11_enterprise.yml
- Benchmarks CIS : https://www.cisecurity.org/cis-benchmarks/

## Scripts de durcissement CIS

Utilisées par [scripts/hardening/](../scripts/hardening/README.md) et le [writeup 13](writeup/13-durcissement-cis-automatise.md)
(checks d'audit 26139-26165 par `auditpol` et noms anglais : vérifiés dans
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/sca/windows/cis_win11_enterprise.yml) :

- Ids, cibles et opérateurs des checks repris tels quels de la politique Wazuh (vérifiée,
  ruleset v4.14.0) : https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/sca/windows/cis_win11_enterprise.yml
- `secedit` : https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
- `auditpol /set` et `/backup` :
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set,
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-backup
- GUID des sous-catégories d'audit, MS-GPAC (vérifiés le 2026-10-25 pour les 27 GUID de la
  famille 03) : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
- `ConvertFrom-Json` (paramètre `-NoEnumerate`, contexte du correctif de rollback PS 5.1) :
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
- Protection LSA (PPL) active par défaut sur une nouvelle installation de Windows 11 22H2+,
  vérification par l'événement Wininit 12 :
  https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- Politique de verrouillage de comptes :
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-policy

## Scénario 6 : mouvement latéral SMB

Utilisées par la [fiche](scenarios/mouvement-lateral-smb.md) et le [writeup 16](writeup/16-scenario-mouvement-lateral-smb.md) :

- T1021.002 SMB/Windows Admin Shares (partages `C$`, `ADMIN$`, `IPC$` « accessibles
  uniquement aux administrateurs ») : https://attack.mitre.org/techniques/T1021/002/
- Restrictions UAC à distance, `LocalAccountTokenFilterPolicy` (0 par défaut = jeton filtré ;
  comptes de domaine non concernés) :
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction
  (exception du compte RID 500 : absente de cette page, à valider)
- Règles natives (vérifiées dans le ruleset v4.14.0) : 67017 dans
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0955-WEF-baseline_rules.xml ;
  92652 et 92657 dans https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0840-win_event_channel.xml ;
  60103, 60104 et 60117 (événement 1102) dans https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0580-win-security_rules.xml
- Syntaxe OS_Regex (`$` = fin du texte, `\$` = dollar littéral) :
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html

## Cartographie MITRE

- Tactiques de la matrice Enterprise : https://attack.mitre.org/tactics/enterprise/
- Techniques citées dans [docs/mitre.md](mitre.md) : liens directs dans le document.

## Scénario 7 : effacement du journal Security

- T1070.001 Clear Windows Event Logs : https://attack.mitre.org/techniques/T1070/001/
- Règles natives (ruleset v4.14.0) : 63103 dans
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0610-win-ms_logs_rules.xml ;
  parents 60001 et 60017 dans https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0575-win-base_rules.xml ;
  60117 dans https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0580-win-security_rules.xml

## Tuning des faux positifs

Utilisées par le [writeup 18](writeup/18-tuning-faux-positifs.md) :

- Règles personnalisées et modification d'une règle native (`overwrite="yes"`) :
  https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- `wazuh-logtest` (options, dont `-l` pour la location) :
  https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
- Règles natives (ruleset v4.14.0) : 92041 dans
  https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0800-sysmon_id_1.xml ;
  67027 dans https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0955-WEF-baseline_rules.xml

## Vulnerability Detection

Utilisées par le [writeup 14](writeup/14-vulnerability-detection.md) (brouillon) :

- Options `<vulnerability-detection>` (`enabled`, `index-status`, `feed-update-interval`,
  `offline-url` en `file://` ou `http(s)://`) :
  https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/vuln-detector.html
- Présentation du module :
  https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html,
  https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html
- Ticket rapproché de l'erreur `array index 14 is out of range` (rapprochement à valider) :
  https://github.com/wazuh/wazuh/issues/38272
- Catalogue CTI (`cti.wazuh.com`, `vd_1.0.0/consumers/vd_4.8.0`, `last_snapshot_link`) :
  relevé dans le lab, procédure officielle hors ligne à retrouver (à valider).

## À explorer

- Guide de preuve de concept Wazuh, pour des scénarios officiels reproductibles.
