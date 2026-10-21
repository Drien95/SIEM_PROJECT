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

## À explorer

- Guide de preuve de concept Wazuh, pour des scénarios officiels reproductibles.
