# VirusTotal

Sources : PDF `VirusTotal_integration` (marxgoo),
https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html,
ruleset Wazuh 4.14 `0490-virustotal_rules.xml`.

## Principe

Le FIM détecte un nouveau fichier ou un fichier modifié. Le **manager** envoie alors son hash
à l'API VirusTotal et produit une alerte enrichie. Le hash est envoyé, pas le fichier.
Cependant, tout ce qu'on dépose soi-même sur VirusTotal devient public.

## Configuration

**1. Clé API** : compte VirusTotal, puis *Profile > API Key*. La clé reste **hors git**.

**2. Manager**, dans `/var/ossec/etc/ossec.conf`. Le PDF place ce bloc dans l'`ossec.conf`
de l'agent Windows, ce qui est faux.

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

`<group>syscheck</group>` limite les requêtes aux alertes FIM. Le PDF l'omet. Avec une clé
publique limitée à 4 requêtes par minute et 500 par jour, le quota serait vite épuisé.

**3. Agent** : surveiller un dossier de dépôt en temps réel (chemin Windows, alors que le PDF
donne `/home/...`) :

```xml
<syscheck>
  <directories realtime="yes">C:\Users\Public\vt-test</directories>
</syscheck>
```

## Règles Wazuh (natives)

| Règle | Niveau | Signification |
|---|---|---|
| 87103 | 3 | Hash inconnu de VirusTotal |
| 87104 | 3 | Connu, aucun moteur ne le détecte |
| **87105** | **12** | Détecté par au moins un moteur (MITRE T1203) |
| 87101 / 87102 / 87106 | 3 | Erreur : quota atteint / clé invalide / délai dépassé |

## Test

Déposer le fichier de test **EICAR** dans le dossier surveillé. Attendu : alerte FIM, puis
87105. Defender risque de supprimer le fichier avant : exclure le dossier de test ou
désactiver temporairement la protection en temps réel, **sur la VM de lab uniquement**.

Recherche : `rule.groups:virustotal`.

**Joué le 2026-10-22** : 554 puis 87105 (niveau 12, 66 moteurs) en ~6 s. Fiche : [malware-fim-virustotal.md](../scenarios/malware-fim-virustotal.md).
