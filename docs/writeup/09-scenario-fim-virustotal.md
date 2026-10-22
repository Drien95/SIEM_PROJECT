# Writeup 09 : troisième scénario, un malware déposé repéré par FIM + VirusTotal

> Un fichier de test EICAR est déposé sur Windows 11. Le FIM voit le fichier apparaître,
> VirusTotal confirme qu'il est malveillant, et Wazuh lève une alerte de niveau 12 six secondes
> plus tard. L'analyse détaillée est dans la fiche
> [`docs/scenarios/malware-fim-virustotal.md`](../scenarios/malware-fim-virustotal.md).
>
> Versions : Wazuh 4.14.9 (manager et agent Windows), Windows 11. Date : 2026-10-22, 21:34
> heure locale.

## 1. Comprendre

### 1.1 Deux questions, deux outils

Devant un nouveau fichier, un analyste se pose deux questions : **qu'est-ce qui a changé ?** et
**est-ce dangereux ?**

- Le **FIM** (*File Integrity Monitoring*) répond à la première. Il connaît l'état de référence
  du dossier, voit le fichier apparaître et calcule son empreinte (hash).
- **VirusTotal** répond à la seconde. Il agrège des dizaines d'antivirus et dit combien
  reconnaissent ce hash.

Wazuh les enchaîne : l'alerte FIM part chez VirusTotal par `wazuh-integratord`. La réponse
revient comme un nouvel événement, qui déclenche sa propre règle. Le cours sur la chaîne des
démons est dans [architecture.md](../architecture.md), le fonctionnement du FIM dans
[integrations/fim.md](../integrations/fim.md).

### 1.2 Pourquoi EICAR

Le fichier EICAR est une chaîne de 68 caractères que tous les antivirus détectent **par
convention**. Il permet de tester toute la chaîne de détection sans manipuler de vrai malware.

## 2. Mise en place

| Où | Action |
|---|---|
| Windows 11 | dossier `C:\Users\Public\vt-test` ; exclusion Defender (`Add-MpPreference -ExclusionPath`) ; `<syscheck>` temps réel sur ce dossier dans l'`ossec.conf` de l'agent ; redémarrage de `WazuhSvc` |
| Manager | bloc `<integration>` `virustotal` avec `<group>syscheck</group>` et la vraie clé API (sur le serveur seulement, jamais dans git) ; `wazuh-analysisd -t` puis redémarrage |

## 3. Déroulé

| Heure | Où | Ce qui se passe |
|---|---|---|
| 21:34 | Windows 11 | `Set-Content ... -NoNewline -Encoding ascii` : `eicar.com`, 68 octets (capture 91) |
| 21:34:13 | Wazuh | **554** niveau 5, « File added to the system » (capture 92) |
| 21:34:19 | Wazuh | **87105** niveau 12, « VirusTotal: Alert - c:\users\public\vt-test\eicar.com - 66 engines detected this file » (capture 93) |

![Alerte VirusTotal 87105](../homelab/screenshots/93-wazuh-87105-virustotal-66-moteurs.png)

## 4. Ce qu'on en apprend

### 4.1 L'antivirus du poste peut masquer le test

Defender supprime EICAR dès sa création. Sans exclusion du dossier, le FIM n'a rien à
rapporter et le test échoue **sans erreur**. C'est le même enseignement que l'agent arrêté du
writeup 07 : un silence dans le SIEM se vérifie, il ne se conclut pas.

### 4.2 Un octet change tout

Sans `-NoNewline`, PowerShell ajoute un retour à la ligne. Le hash n'est plus celui d'EICAR, et
VirusTotal répond « inconnu » (87103, niveau 3). La détection par hash est exacte, mais
fragile : un attaquant qui modifie un seul octet de son outil sort des listes. C'est pourquoi on
la complète par des détections de **comportement** (Sysmon, prochain scénario).

### 4.3 Un quota à respecter

L'API gratuite accepte 4 requêtes par minute. `<group>syscheck</group>` n'envoie que les
alertes FIM, et le FIM temps réel reste limité à quelques dossiers.

### 4.4 Ce qui manque : la remédiation automatique

Wazuh détecte, mais le fichier reste en place. L'étape suivante est une réponse active qui le
supprime sur 87105, construite comme `block-ip-win` (writeup 07). Elle est notée dans la
[roadmap](../roadmap.md).

## 5. Résultats dans notre lab

| Test | Attendu | Obtenu |
|---|---|---|
| Fichier EICAR de 68 octets | 68 octets | ✅ capture 91 |
| Alerte FIM à la création | 554 | ✅ 21:34:13 |
| Enrichissement VirusTotal | 87105, niveau 12 | ✅ 21:34:19, 66 moteurs |
| Délai dépôt → alerte de niveau 12 | quelques secondes | ✅ ~6 s |
| Suppression automatique du fichier | réponse active sur 87105 | ⏳ à construire |

Sources : voir la [fiche du scénario](../scenarios/malware-fim-virustotal.md).
