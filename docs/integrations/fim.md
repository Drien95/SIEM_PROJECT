# File Integrity Monitoring (FIM)

Sources : PDF `File_integrity_monitoring` (marxgoo), UsmanPrime/Wazuh-Setup,
https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html

## Pourquoi

Un attaquant modifie le système : un rançongiciel chiffre des fichiers, un intrus efface ou
modifie des journaux, un malware dépose un binaire. Le FIM alerte sur les créations,
modifications et suppressions. Il est exigé par PCI DSS, HIPAA et ISO 27001.

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
une alerte pour l'ajout, une par modification et une pour la suppression. UsmanPrime relève des
niveaux 5 et 7. Les IDs exacts sont à relever dans notre lab.
