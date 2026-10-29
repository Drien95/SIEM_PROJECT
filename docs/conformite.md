# Lecture conformité : ce que les détections apportent à PCI DSS, SOC 2 et CIS

> Pour un lecteur conformité (GRC, audit, IAM). Chaque détection du lab est reliée aux exigences
> qu'elle aide à satisfaire. Mis à jour le 2026-10-29.
>
> **À lire avant le tableau.** Le lab n'a ni données de carte ni périmètre d'audit : il montre le
> **mécanisme technique** derrière une exigence, pas sa conformité. Les rattachements sont faits
> par l'auteur (**déduit**), pas par un QSA ou un auditeur SOC 2. Ce qui est **vérifié**, c'est
> la détection elle-même, jouée en live et documentée dans le writeup cité.

Référentiels : PCI DSS **v4.0.1**, SOC 2 (Trust Services Criteria 2017, points of focus révisés
2022), CIS Controls **v8**. Sources en fin de page.

## 1. Le tableau

| Détection (règle Wazuh) | Ce que le lab prouve | PCI DSS v4.0.1 | SOC 2 | CIS Controls v8 | Preuve |
|---|---|---|---|---|---|
| Collecte centralisée : agent Windows (Security, Sysmon, Defender), syslog pfSense, Suricata | les journaux de 3 types de sources arrivent sur un serveur central, en temps réel | 10.2.1 (journaux activés), 10.3.3 (copie rapide vers un serveur central) | CC7.2 | 8.2, 8.9 | [writeups 02](writeup/02-syslog-pfsense.md), [04](writeup/04-agent-windows-sysmon.md), [10](writeup/10-scenario-suricata-nids.md) |
| Brute force : 60122 → 60204 → réponse active → **100400** | les échecs sont vus un par un, la rafale bloque l'IP 180 s, un succès après rafale monte au niveau 12 | 10.2.1.4 (tentatives d'accès invalides), 10.4.1.1 (revue automatisée) ; 8.3.4 (verrouillage) seulement par analogie, la réponse active bloque une IP, pas un compte | CC6.1, CC7.2, CC7.4 | 8.11, 13.1 | [06](writeup/06-scenario-brute-force-smb.md), [07](writeup/07-regles-et-reponse-active.md) |
| Effacement du journal Security **100250** ; retrait d'audit **100251** | effacer ou couper la journalisation lève une alerte de niveau 12, et ce que le SIEM a déjà reçu reste intact | **10.2.1.6** (arrêt ou pause des journaux), 10.3.2 (journaux protégés contre la modification), **10.7.2** (défaillance d'un contrôle critique, dont la journalisation) | CC7.2 | 8.2 | [17](writeup/17-scenario-effacement-journaux.md), [26](writeup/26-du-triage-au-tuning.md) |
| Tâche planifiée en SYSTEM **100270**, **100271** ; créée puis supprimée en < 60 s **100273** | une action d'administrateur qui donne les pleins pouvoirs est tracée, même si la tâche a disparu 4 s plus tard | 10.2.1.2 (actions des comptes administrateurs), 10.2.1.7 (création et suppression d'objets système) | CC6.1, CC7.2 | 5.4, 8.5 | [21](writeup/21-scenario-tache-planifiee-system.md), [26](writeup/26-du-triage-au-tuning.md) |
| Accès à LSASS **100220** (+ liste blanche 100221) | une lecture de la mémoire des identifiants est signalée, les outils légitimes connus sont filtrés | pas d'exigence directe ; relève de 10.4.1.1 (revue automatisée) | CC6.1, CC7.2 | 8.11 | [15](writeup/15-detection-acces-identifiants-lsass.md), [25](writeup/25-dashboard-couverture-mitre.md) |
| Persistance par clé Run **100230** (+ liste blanche 100231) | une modification de la configuration de démarrage est signalée | 11.5.2 (détection de changement, ici sur le registre : déduit) | CC7.1, CC7.2 | 8.5 | [11](writeup/11-scenario-persistance-run-key.md), [18](writeup/18-tuning-faux-positifs.md) |
| FIM 554 → VirusTotal 87105 | un fichier malveillant (EICAR) déposé est vu et qualifié en ~6 s | **11.5.2** (mécanisme de détection de changement), 5.2.2 (détection de logiciel malveillant) | CC6.8, CC7.2 | 10.1, 3.14 | [09](writeup/09-scenario-fim-virustotal.md) |
| Blocage Defender **100290** | un blocage antivirus remonte au SIEM, **une fois le canal Defender ajouté** | **5.3.4** (journaux anti-malware activés et conservés), 10.7.2 | CC6.8, CC7.2 | 10.1, 8.2 | [24](writeup/24-scenario-telechargement-certutil.md) |
| Accès SMB depuis le segment d'attaque **100240** | une tentative d'accès aux partages d'administration (refusée) est tracée | 10.2.1.4 (accès invalide), 1.3.1 (trafic entrant restreint, vu par pfSense) | CC6.6, CC7.2 | 13.1 | [16](writeup/16-scenario-mouvement-lateral-smb.md) |
| Scans : pfSense **100303**, Suricata **100210**, **100211** | deux capteurs réseau indépendants voient un scan, dont un scan de vulnérabilités par signature maison | **11.5.1** (détection d'intrusion réseau), 10.2.1 (journaux des pare-feu) | CC6.6, CC7.2 | 13.3, 13.1 | [08](writeup/08-scenario-scan-nmap.md), [10](writeup/10-scenario-suricata-nids.md), [23](writeup/23-scenario-reconnaissance-vuln-scan.md) |
| Archive puis exfiltration HTTP **100282** (corrélation) | deux actions anodines seules deviennent une alerte de niveau 14 ensemble | 10.4.1.1, 12.10.5 (le plan de réponse couvre les alertes de supervision) | CC7.2, CC7.3 | 13.1, 3.13 (déduit) | [22](writeup/22-scenario-collection-exfiltration.md) |
| PowerShell encodé **100101**, suppression des clichés **100260** | des lignes de commande malveillantes sont détectées par leur contenu | 10.4.1.1 | CC7.2 | **8.8** (journaux de ligne de commande), 2.7 | [19](writeup/19-scenario-suppression-cliches.md), [20](writeup/20-scenario-powershell-encode.md) |
| SCA, benchmark CIS Windows 11 (24 % puis 25 %) | la posture est mesurée, un check corrigé passe de Failed à Passed, la preuve est horodatée | **2.2.1** (standards de configuration), 2.2.4 | CC7.1 | **4.1** | [12](writeup/12-sca-cis-windows11.md), [13](writeup/13-durcissement-cis-automatise.md) |
| Tickets de triage puis tuning | une alerte est qualifiée, ses manques deviennent des règles | **10.4.3** (anomalies identifiées traitées), 12.10.5 | CC7.3, CC7.4 | 13.11, 17.4 | [triage](triage/README.md), [26](writeup/26-du-triage-au-tuning.md) |

### Ce que le lab ne couvre pas, côté conformité

| Exigence | Pourquoi ce n'est pas couvert |
|---|---|
| PCI DSS 6.3.1, 11.3.1 ; CIS 7.5 (vulnérabilités) | Vulnerability Detection de Wazuh 4.14.9 n'a produit **aucun résultat** ([writeup 14](writeup/14-vulnerability-detection.md)) |
| PCI DSS 10.5.1 (12 mois de rétention, 3 mois disponibles) | rétention et rotation des index non configurées ni testées |
| PCI DSS 10.6 (synchronisation horaire) | NTP des machines non vérifié ; les horodatages des writeups sont cohérents, sans preuve formelle |
| PCI DSS 10.3.2 (intégrité des journaux sur le serveur) | ce qui est stocké sur le manager n'est ni signé ni immuable dans le lab |
| PCI DSS 7.x, 8.x (gestion des identités et des droits) | pas d'Active Directory : pas de comptes de domaine, de groupes, de revue d'accès |

## 2. Constats utiles à un auditeur

**1. Les étiquettes PCI DSS du ruleset Wazuh sont en numérotation v3.2.1 (vérifié).** Les règles
natives portent des groupes `pci_dss_10.2.4`, `pci_dss_10.2.5`, `pci_dss_10.6.1`,
`pci_dss_11.4`, `pci_dss_8.1.2` : c'est la numérotation de PCI DSS **v3.2.1**, retirée le
31 mars 2024 (date publiée par le PCI SSC, à revérifier dans la bibliothèque documentaire). Exemple, la native 60112 (changement de politique d'audit) :

```xml
<group>policy_changed,pci_dss_10.6.1,gpg13_10.1,...,tsc_CC7.2,tsc_CC7.3,</group>
```

En v4.0.1, ce même événement relève de 10.2.1.6 et 10.7.2. Conséquence : le tableau de bord
« PCI DSS » de Wazuh ne peut pas servir tel quel de preuve pour un audit v4. Il faut une table de
correspondance, celle de la section 1 en est une ébauche.
Source : `ruleset/rules/0580-win-security_rules.xml`, Wazuh v4.14.0 (lien en fin de page).

**2. Nos règles locales sont presque invisibles pour les vues de conformité (vérifié).** Sur les
26 règles de [`local_rules.xml`](https://github.com/Drien95/SIEM_PROJECT/blob/main/configs/manager/local_rules.xml),
une seule (100400) porte un groupe `pci_dss_*`, aucune un groupe `tsc_*`. Les vues de conformité
du dashboard filtrent sur ces champs (déduit) : nos meilleures détections n'y apparaissent pas.
Piste : ajouter les groupes à chaque règle locale (à faire, à valider dans le dashboard).

**3. Un contrôle peut fonctionner et rester invisible (vérifié).** Defender bloquait le
téléchargement par `certutil`, mais Wazuh ne collectait pas son journal : rien au SIEM. Pour un
auditeur, « l'antivirus est installé » et « ses événements sont centralisés » (PCI DSS 5.3.4)
sont deux preuves distinctes ([writeup 24](writeup/24-scenario-telechargement-certutil.md)).

**4. Un score de conformité peut mentir (vérifié).** Sur un Windows en français, le SCA marque
« Failed » des réglages d'audit correctement appliqués : le check cherche un texte anglais. Un
score CIS n'est une preuve qu'après vérification de l'instrument
([writeup 13](writeup/13-durcissement-cis-automatise.md)).

**5. Une absence de preuve n'est pas une preuve d'absence (vérifié).** L'archivage brut
(`logall_json`) était coupé depuis 4 jours sans que rien ne le signale ; chaque « 0 événement »
relevé pendant ce temps ne prouvait rien ([writeup 25](writeup/25-dashboard-couverture-mitre.md)).
C'est exactement le cas que vise 10.7.2 : détecter la panne d'un mécanisme de journalisation.

## Sources

- PCI DSS v4.0.1, bibliothèque documentaire du PCI SSC : https://www.pcisecuritystandards.org/document_library/
- AICPA, 2017 Trust Services Criteria (Revised Points of Focus, 2022) : https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- CIS Critical Security Controls v8 : https://www.cisecurity.org/controls/v8
- Wazuh, conformité PCI DSS : https://documentation.wazuh.com/current/compliance/pci-dss/index.html
- Étiquettes du ruleset Wazuh v4.14.0 : https://github.com/wazuh/wazuh/tree/v4.14.0/ruleset/rules
