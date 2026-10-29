# Rapport d'évaluation : Wazuh 4.14.9

> Objectif de départ du projet : savoir ce que vaut Wazuh une fois déployé, au-delà de la
> plaquette. Ce rapport tire le bilan de 26 writeups et de 14 scénarios d'attaque joués en live,
> du 2026-10-20 au 2026-10-29 (scénarios 1 à 13, plus le 5b). Chaque note renvoie à sa preuve. Ce que ce lab ne permet pas de
> juger est listé en [section 5](#5-ce-que-ce-lab-ne-prouve-pas).
>
> Version évaluée : Wazuh **4.14.9** (OVA tout-en-un), agent Windows 4.14.9, Windows 11 en
> français, pfSense CE 2.9.0 avec Suricata.

## 1. Verdict

Wazuh est un **bon SIEM pour qui a le temps et les compétences de le régler**. La collecte, la
corrélation et le langage de règles sont solides, et la couverture conformité est réelle. Mais
le ruleset natif rate des cas classiques, la configuration par défaut laisse des angles morts,
un module (Vulnerability Detection) n'a rien produit, et plusieurs pannes sont **silencieuses**.
Sur les 14 scénarios joués, **13 s'appuient sur au moins une règle locale** ; seul le FIM + VirusTotal tient avec les règles natives seules.

## 2. Grille

✅ fonctionne tel quel · ⚠️ fonctionne après réglage ou avec réserve · ❌ ne fonctionne pas dans ce lab

| Domaine | Note | Constat | Preuve |
|---|---|---|---|
| Déploiement (OVA) | ⚠️ | démarre vite, mais racine de 25 Go sur un disque de 50 Go, pleine dès l'installation (index en lecture seule) ; services manager et dashboard non activés au démarrage ; identifiants par défaut publics | [writeup 01](writeup/01-homelab.md), [04](writeup/04-agent-windows-sysmon.md) |
| Agent Windows et Sysmon | ✅ | enrôlement simple, configuration centralisée (`agent.conf`) poussée à l'agent | [writeup 04](writeup/04-agent-windows-sysmon.md) |
| Collecte par défaut | ⚠️ | le journal **Defender** n'est pas collecté : un blocage antivirus reste invisible au SIEM | [writeup 24](writeup/24-scenario-telechargement-certutil.md) |
| Syslog réseau (pfSense) | ⚠️ | reçu, mais décodeur et règles locales nécessaires pour exploiter `filterlog` | [writeup 02](writeup/02-syslog-pfsense.md), [08](writeup/08-scenario-scan-nmap.md) |
| Suricata via syslog | ⚠️ | en-tête RFC 5424 non lu par défaut (décodeur local) ; les alertes EVE complètes **n'arrivent jamais** (trop grosses pour un datagramme UDP), à alléger | [writeups 10](writeup/10-scenario-suricata-nids.md), [23](writeup/23-scenario-reconnaissance-vuln-scan.md) |
| Ruleset natif | ⚠️ | large, étiqueté MITRE et conformité ; mais aucune règle sur `vssadmin delete shadows` ni sur le 4699, règles Sysmon dépendantes d'un parent souvent absent, natives au niveau 0 (92300), description vide (62123), exclusion `IPC$` inopérante (67017) | [19](writeup/19-scenario-suppression-cliches.md), [20](writeup/20-scenario-powershell-encode.md), [11](writeup/11-scenario-persistance-run-key.md), [24](writeup/24-scenario-telechargement-certutil.md), [16](writeup/16-scenario-mouvement-lateral-smb.md) |
| Étiquettes MITRE natives | ⚠️ | à relire : « possible RDP » sur du SMB, T1531 sur un échec de connexion, T1203 sur tout fichier VirusTotal | [mitre.md § 5](mitre.md#5-étiquettes-mitre-à-ne-pas-reprendre-telles-quelles) |
| Langage de règles | ✅ | `if_sid`, PCRE2, corrélation `frequency` / `same_field` : deux corrélations écrites et validées (100282, 100273) | [writeups 22](writeup/22-scenario-collection-exfiltration.md), [26](writeup/26-du-triage-au-tuning.md) |
| Outillage de test des règles | ❌ | `wazuh-logtest` ne reproduit pas le décodage EventChannel : toute règle Windows se valide en live | [writeup 18](writeup/18-tuning-faux-positifs.md) |
| Pièges silencieux | ⚠️ | une règle locale peut masquer des natives sœurs (100100 supprimée) ; antislashs doublés : une liste blanche fausse ne lève aucune erreur | [writeups 20](writeup/20-scenario-powershell-encode.md), [25](writeup/25-dashboard-couverture-mitre.md) |
| Réponse active | ✅ | blocage de l'IP attaquante 180 s dans le pare-feu Windows, validé en live | [writeup 07](writeup/07-regles-et-reponse-active.md) |
| FIM + VirusTotal | ✅ | fichier malveillant qualifié en ~6 s ; quota de l'API gratuite (4 requêtes/min) à respecter | [writeup 09](writeup/09-scenario-fim-virustotal.md) |
| SCA (conformité CIS) | ⚠️ | mesure lisible, rattachée à 7 référentiels ; **faux échecs** sur un Windows en français | [writeups 12](writeup/12-sca-cis-windows11.md), [13](writeup/13-durcissement-cis-automatise.md) |
| Vulnerability Detection | ❌ | flux incrémental en échec, puis base de 10 Go chargée hors ligne et Inventory toujours vide ; cause non établie | [writeup 14](writeup/14-vulnerability-detection.md) |
| Dashboard | ✅ | OpenSearch Dashboards : visualisations DQL libres, dashboard MITRE construit en une séance | [writeup 25](writeup/25-dashboard-couverture-mitre.md) |
| Vues de conformité | ⚠️ | étiquettes PCI DSS en numérotation **v3.2.1** ; les règles locales n'y apparaissent que si on les étiquette | [conformité](conformite.md#2-constats-utiles-à-un-auditeur) |
| Exploitation | ⚠️ | archivage brut (`logall_json`) désactivé par défaut, puis coupé 4 jours sans alerte | [writeup 25](writeup/25-dashboard-couverture-mitre.md) |

## 3. Forces

1. **Gratuit et complet** : SIEM, agent, FIM, SCA, réponse active et dashboard dans une seule
   installation, sans licence au volume.
2. **Un vrai langage de détection** : règles enfants, PCRE2, corrélation temporelle sur un champ
   commun. On peut écrire exactement la détection voulue, et la versionner dans git.
3. **Transparent** : ruleset public, configuration en XML lisible. Quand une native ne sonne
   pas, on peut lire pourquoi (sœur évaluée d'abord, champ absent).
4. **Orienté conformité** : SCA par benchmark CIS, étiquettes PCI DSS, SOC 2 (`tsc_*`), NIST,
   HIPAA, RGPD sur les règles natives.

## 4. Limites

1. **Le natif ne suffit pas.** 13 scénarios sur 14 s'appuient sur une règle locale. Sans
   ingénieur détection, Wazuh détecte moins que ce qu'il affiche.
2. **Les pannes ne font pas de bruit.** Canal non collecté, archivage coupé, liste blanche qui ne
   correspond jamais, règle qui en masque d'autres : rien de tout cela ne lève d'erreur.
3. **Pas de banc de test fiable pour Windows.** `wazuh-logtest` étant infidèle sur EventChannel,
   chaque règle Windows se teste en rejouant l'attaque.
4. **Un module majeur en échec** dans cette version (Vulnerability Detection).
5. **Sensible à la langue du système** : SCA en français, valeurs d'audit tantôt localisées,
   tantôt en anglais.

## 5. Ce que ce lab ne prouve pas

Les limites du banc d'essai, à lire avant de reprendre un chiffre de ce projet :

- **Pas d'Active Directory.** Un seul Windows hors domaine : ni Kerberos, ni GPO, ni comptes de
  domaine. Les attaques les plus courantes en entreprise (Kerberoasting, DCSync, pass-the-hash
  vers un contrôleur) ne sont pas testées.
- **Une seule machine supervisée.** Pas de parc, pas d'agent Linux ou macOS, pas de cloud
  (Microsoft 365, Azure). La tenue en charge de Wazuh n'est pas évaluée.
- **Pas de volume réel.** Un utilisateur, quelques jours d'historique, aucun trafic métier. Les
  taux de faux positifs (dont « 0 sur 6 tâches ») décrivent ce lab, pas un environnement de
  production.
- **L'attaquant connaît les règles.** Les scénarios sont joués par l'auteur, qui écrit ensuite la
  détection : c'est de la validation, pas un test à l'aveugle (pas d'exercice red team).
- **Pas d'opération dans la durée.** Ni astreinte, ni délai de détection (MTTD) mesuré, ni
  rétention de 12 mois, ni montée de version.
- **Pas de comparaison.** Aucun autre SIEM (Splunk, Microsoft Sentinel, Elastic) n'a été monté
  dans les mêmes conditions : ce rapport juge Wazuh seul.

## 6. À qui le recommander

| Contexte | Recommandation |
|---|---|
| PME ou équipe sécurité réduite, budget serré, besoin de conformité (PCI DSS 10.x, 11.5, CIS) | **oui**, à condition d'avoir une personne capable d'écrire et de maintenir des règles |
| Laboratoire, formation, montée en compétences détection | **oui** : tout est lisible, rien n'est caché derrière une interface |
| Organisation sans compétence détection, qui attend un produit clé en main | **non**, ou via un prestataire qui fournit le ruleset et le suivi |
| Besoin d'inventaire de vulnérabilités fiable | **pas sur la 4.14.9** d'après ce lab ; outil dédié ou version ultérieure à tester |
| Gros volumes, multi-sites, haute disponibilité | **non évalué** ici |

## 7. Si c'était à refaire

- Activer `logall_json` et la collecte Defender **dès le départ**, et surveiller la fraîcheur
  des sources.
- Monter le poste Windows en anglais en plus du français, pour départager les problèmes de
  langue.
- Étiqueter chaque règle locale (MITRE, PCI DSS v4, SOC 2) au moment de l'écrire.
- Ajouter un contrôleur de domaine avant d'étendre les scénarios.
