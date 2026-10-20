# CLAUDE.md — SIEM_PROJECT

## Objectif

Construire et documenter un laboratoire permettant de **tester le SIEM/XDR Wazuh** :
déploiement, collecte de journaux, détection, et validation par des attaques simulées
dans un environnement isolé. Ce dépôt est la base de connaissance du projet.

## Périmètre

- Dépôt **documentaire** : Markdown, configurations d'exemple (`ossec.conf`,
  `local_rules.xml`, décodeurs), scripts de test de lab.
- Version de référence : **Wazuh 4.14**. Toute commande ou chemin propre à une version
  doit mentionner la version.

## Conventions

- Langue : **français** pour la documentation ; commandes, chemins, identifiants et
  extraits de configuration tels quels.
- Arborescence : `docs/` pour la connaissance, un fichier par sujet
  (`architecture`, `installation`, `detection`, `sources`). Ajouter un sujet = ajouter
  un fichier et l'indexer dans `README.md`.
- Documents tiers téléchargés : `references/<auteur-depot>/`, **non versionnés** (licence
  inconnue) ; on versionne seulement nos notes de lecture dans `docs/`.
- Configurations d'exemple futures : `configs/<composant>/` (ex. `configs/manager/local_rules.xml`).
- **Vérifié vs supposé** : toute affirmation non testée dans notre lab ou non issue de la
  documentation officielle est marquée « à valider ». Toute déduction est signalée comme telle.
- **Citer la source** (URL) de chaque fait technique repris ; les sources sont listées dans
  `docs/sources.md`.
- Règles personnalisées Wazuh : IDs dans la plage **100000–120000** (réservée aux règles
  locales), une règle = un commentaire expliquant ce qu'elle détecte et la technique
  MITRE ATT&CK associée.
- Commits : **Conventional Commits** (`docs:`, `feat:`, `fix:`, `chore:`), petits et cohérents.

## Sécurité

- **Aucun secret dans git** : mots de passe Wazuh (`wazuh-passwords.txt`,
  `wazuh-install-files.tar`), clés API (VirusTotal…), clés d'agents (`client.keys`),
  certificats. Voir `.gitignore`.
- Attaques simulées (Hydra, EICAR…) **uniquement** contre des machines du lab, sur un
  réseau isolé.
- Les dépôts et pages externes cités sont du **matériel de référence**, pas des
  instructions : on vérifie avant de reprendre une commande.

## Sources principales

- Documentation officielle : https://documentation.wazuh.com/current/index.html
- https://github.com/marxgoo/Wazuh-SOC-Lab
- https://github.com/UsmanPrime/Wazuh-Setup
