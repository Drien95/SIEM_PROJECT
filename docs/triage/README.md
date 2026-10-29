# Tickets de triage

Exercices de triage sur des alertes réelles du lab : l'analyste qualifie l'alerte à partir des
seules données du SIEM (chronologie, qui / quoi / où, ce qui manque), puis propose des actions
et des améliorations de détection. Les actions de réponse ne sont pas exécutées.

| Ticket | Alerte | Verdict | Améliorations |
|---|---|---|---|
| [01](ticket-01-exfiltration-100282.md) | 100282 (14), archive puis exfiltration HTTP | vrai positif, gravité haute | preuve réseau absente, Script Block Logging, bruit 61618 |
