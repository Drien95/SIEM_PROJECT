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

## À explorer

- Guide de preuve de concept Wazuh, pour des scénarios officiels reproductibles.
