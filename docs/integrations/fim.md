# File Integrity Monitoring (FIM)

Sources : PDF `File_integrity_monitoring` (marxgoo), UsmanPrime/Wazuh-Setup,
https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html,
https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html,
https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0015-ossec_rules.xml

## Pourquoi

Un attaquant modifie le système : un rançongiciel chiffre des fichiers, un intrus efface ou
modifie des journaux, un malware dépose un binaire. Le FIM alerte sur les créations,
modifications et suppressions. Il est exigé par PCI DSS, HIPAA et ISO 27001.

## Comment ça marche

Le FIM (*File Integrity Monitoring*, module `syscheck`) fonctionne en deux temps :

1. **Baseline** : au premier scan, l'agent relève pour chaque fichier surveillé sa taille, ses
   permissions, son propriétaire, ses dates et ses empreintes **MD5, SHA1 et SHA256**. Ces
   valeurs sont stockées côté manager (base de l'agent).
2. **Comparaison** : à chaque scan suivant, ou à chaque événement en mode temps réel, il
   recalcule et compare. Une différence déclenche un événement : fichier **ajouté**,
   **modifié** ou **supprimé**.

| Mode | Quand l'alerte arrive | Coût |
|---|---|---|
| Scan périodique (par défaut) | au prochain passage : `<frequency>` vaut 43200 s, soit 12 h, dans la configuration par défaut du manager | faible |
| `realtime="yes"` sur un dossier | quelques secondes après le changement (surveillance du système de fichiers) | plus élevé, à réserver aux dossiers sensibles |

`check_all="yes"` active tous les contrôles (taille, permissions, propriétaire, dates, les trois
hash). Le hash est l'élément clé : c'est lui qui permet de demander à VirusTotal si le fichier
est connu comme malveillant.

### Règles natives (ruleset v4.14.0, `0015-ossec_rules.xml`)

| Règle | Niveau | Événement |
|---|---|---|
| 554 | 5 | *File added to the system* (fichier ajouté) |
| 550 | 7 | *Integrity checksum changed* (fichier modifié) |
| 553 | 7 | *File deleted* (fichier supprimé) |

Elles portent le groupe `syscheck` et, entre autres, l'étiquette PCI DSS 11.5. Les niveaux 5 et 7
relevés par UsmanPrime correspondent.

### Ce qu'un analyste SOC en fait

- **Rançongiciel** : des centaines de 550 en quelques secondes sur un même poste, c'est le
  chiffrement en cours.
- **Dépôt de malware** : une 554 dans un dossier de téléchargement ou de démarrage, avec un hash
  à vérifier.
- **Defacement** : modification des fichiers d'un site web.
- **Effacement de traces** : suppression ou modification de journaux (553, 550).
- **Conformité** : PCI DSS (exigence 11.5), HIPAA, ISO 27001 demandent ce contrôle.

### FIM + VirusTotal : « ça a bougé » puis « c'est malveillant »

Le FIM dit **qu'un fichier a bougé** et fournit son hash. Il ne sait pas si le fichier est
dangereux. L'intégration VirusTotal (`wazuh-integratord`) envoie ce hash à VirusTotal. La réponse
revient dans Wazuh comme un nouvel événement : **87105** (niveau 12) si des moteurs détectent le
fichier, 87103 s'il est inconnu. Une réponse active peut alors supprimer le fichier. C'est le
scénario 3 de la [roadmap](../roadmap.md). Voir [virustotal.md](virustotal.md) et la
[chaîne des démons](../architecture.md#comment-wazuh-fonctionne--ossecconf-et-les-démons).

## Configuration (agent)

Fichier : `C:\Program Files (x86)\ossec-agent\ossec.conf` sous Windows,
`/var/ossec/etc/ossec.conf` sous Linux. Le PDF donne le chemin Linux pour un agent Windows,
ce qui est une erreur.

```xml
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes"
               recursion_level="2">C:\Users\Public\fim-test</directories>
</syscheck>
```

| Attribut | Effet |
|---|---|
| `realtime="yes"` | Alerte immédiate au lieu d'attendre le scan périodique |
| `check_all="yes"` | Contrôle hash, taille, propriétaire, permissions, dates |
| `report_changes="yes"` | Joint le diff du contenu (fichiers texte). Éviter sur des dossiers contenant des secrets. |
| `recursion_level` | Profondeur de sous-dossiers surveillée (0 = dossier seul) |

Redémarrage : `Restart-Service -Name WazuhSvc` (Windows) ou
`sudo systemctl restart wazuh-agent` (Linux).

## Test

1. Créer `test.txt` dans le dossier surveillé.
2. Le modifier deux fois.
3. Le supprimer.

Résultat attendu dans *File Integrity Monitoring* ou *Threat Hunting* (`rule.groups:syscheck`) :
une alerte pour l'ajout (554), une par modification (550) et une pour la suppression (553).
IDs du ruleset natif, à confirmer dans notre lab.
