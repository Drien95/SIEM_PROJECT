# Lecture data : volumes d'alertes et faux positifs, chiffres à l'appui

> Pour un lecteur data (analyste, BI). Un SIEM est d'abord un pipeline de données : collecte,
> normalisation, règles, agrégats. Cette page reprend les chiffres mesurés dans le lab, la
> méthode qui les a produits et ce qu'ils valent. Mis à jour le 2026-10-29.
>
> Source des chiffres : index `wazuh-alerts-*` (dashboard) et fichiers `alerts.json` /
> `archives.json` du manager, [writeups 25](writeup/25-dashboard-couverture-mitre.md) et
> [26](writeup/26-du-triage-au-tuning.md).

## 1. Le pipeline, vu comme une chaîne de données

| Étape | Dans Wazuh | Équivalent data |
|---|---|---|
| Collecte | agent Windows (EventChannel), syslog UDP (pfSense, Suricata) | ingestion |
| Décodage | décodeurs : extraire les champs d'une ligne brute | parsing, normalisation du schéma |
| Règles | arbre de règles : chaque événement reçoit un niveau (0 à 15) | classification |
| Corrélation | `frequency`, `timeframe`, `same_field` | fenêtre glissante, jointure sur une clé |
| Stockage | index OpenSearch `wazuh-alerts-*` | entrepôt |
| Dashboard | visualisations DQL | reporting |

Schéma : [pipeline Wazuh](diagrams/pipeline-wazuh.png).

## 2. Les volumes mesurés

| Mesure | Valeur | Période | Statut |
|---|---|---|---|
| Alertes critiques (niveau ≥ 12) | **1 024** | 10 jours au 2026-10-29 | vérifié (dashboard) |
| Alertes Credential Access (niveau ≥ 8) | ~650, surtout le brute force | idem | vérifié |
| Trafic pfSense autorisé (100301, niveau 3) | pic de **14 000** en un jour | 2026-10-23 | vérifié |
| Accès LSASS 100220 (niveau 12) | **489** | surtout le 2026-10-25 | vérifié |
| svchost 61618 (niveau 12) | **93** | une journée | vérifié |
| Alertes Impact, Lateral Movement, Exfiltration | 1 ou 2 chacune | 10 jours | vérifié |

**Ce que la distribution dit.** Les volumes s'étalent sur quatre ordres de grandeur (1 à
14 000). En échelle linéaire, les tactiques rares, qui sont justement les plus graves,
disparaissent du graphique : le dashboard est donc en **échelle logarithmique**. Effet de bord
assumé : une tactique à 1 alerte a une barre de longueur nulle (log 1 = 0).

## 3. D'où vient le bruit

Au moins **582 des 1 024 alertes critiques (57 %)** s'expliquent par deux causes non
malveillantes : 489 alertes LSASS de mise au point et 93 svchost légitimes (calcul **déduit**
des writeups 25 et 26, dont les périodes se recouvrent ; à recompter sur une fenêtre fixe).

| Source de bruit | Volume | Cause établie | Traitement | Statut |
|---|---|---|---|---|
| 100220, accès LSASS par `taskmgr.exe` | 489 au dashboard ; dans les fichiers d'alertes, les 501 alertes en masque 0x1000 tombent toutes le 25/10 entre 17 h et 18 h UTC | **artefact** : essais de dump pendant la mise au point du scénario 5 | aucun : documenté, pas effacé | vérifié par la répartition horaire |
| 61618, svchost « suspect » | 93 par jour, niveau 12 | Sysmon démarre après `services.exe`, le parent n'est jamais transmis, l'exception native ne s'applique pas | liste blanche **100120** sur la cause (GUID parent nul + compte de service + binaire exact) | vérifié : 93 avant, 93 après le redémarrage de deux services |
| 100220, outils légitimes (WmiPrvSE, agent Wazuh, Defender, VMware Tools) | ~60, le 28/10 | outils qui inspectent LSASS normalement | liste blanche **100221**, chemins complets ancrés | déployée, **validation en attente** |
| 100230, Microsoft Edge écrit dans la clé Run | non compté | auto-démarrage d'Edge | liste blanche **100231** | vérifié (vrai positif toujours détecté) |
| 60228, création de tâche (niveau 4) | toutes les tâches | native trop large | règles étroites 100270 / 100271 | **0 faux positif sur 6** tâches légitimes rejouées (échantillon faible) |

**Méthode, la même à chaque fois** : compter par attribut (processus source, masque d'accès,
heure), formuler une hypothèse, la tester sur les données, filtrer sur la **cause** et pas sur
le symptôme, puis vérifier qu'un vrai positif sonne encore. Deux hypothèses sur quatre étaient
fausses au [writeup 26](writeup/26-du-triage-au-tuning.md) ; la répartition par heure a tranché
le cas LSASS en une commande.

## 4. Pièges de données rencontrés

| Piège | Effet | Leçon |
|---|---|---|
| `rule.id:100*` en DQL attrape aussi la native **1004** | règle étrangère dans la table des règles locales | un joker sur un identifiant numérique est une approximation ; filtrer aussi par niveau |
| Antislashs **doublés** dans les champs Windows (`C:\\Windows\\…`) | une liste blanche qui ne correspond jamais, **sans erreur** | tester un filtre sur la forme réelle des données, pas sur ce qu'on croit qu'elles sont |
| Archivage brut coupé 4 jours | chaque « 0 événement » ne prouvait rien | vérifier la fraîcheur d'une source (date du fichier) avant de lire un zéro |
| Joker shell développé sans les droits (`zcat` + `2>/dev/null`) | résultat vide trompeur | ne pas masquer les erreurs d'une requête de comptage |
| Une action, plusieurs événements (`reg.exe` crée ses propres traces) | la méthode de test fabrique du bruit | séparer le bruit du test du bruit du système |

## 5. Ce qui n'est pas mesuré

- **Délai de détection de bout en bout** (action → alerte au dashboard) : non mesuré. Seuls des
  écarts ponctuels sont connus : VirusTotal ~6 s après le dépôt du fichier, corrélation 100282
  49 ms après l'archive (horodatages des alertes).
- **Taux de faux positifs sur la durée** : le lab a un seul utilisateur et quelques jours
  d'historique. Les taux ci-dessus décrivent ce lab, pas un parc.
- **Coût de stockage** : non suivi (le disque de 25 Go de l'OVA était plein dès l'installation,
  [writeup 01](writeup/01-homelab.md)).

Piste data : exporter `alerts.json` vers un outil BI (Power BI) pour suivre le volume par règle
et par jour, et mesurer l'effet de chaque liste blanche avant et après (à faire).
