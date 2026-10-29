# Tickets de triage

Exercices de triage sur des alertes réelles du lab : l'analyste qualifie l'alerte à partir des
seules données du SIEM (chronologie, qui / quoi / où, ce qui manque), puis propose des actions
et des améliorations de détection. Les actions de réponse ne sont pas exécutées.

| Ticket | Alerte | Verdict | Améliorations |
|---|---|---|---|
| [01](ticket-01-exfiltration-100282.md) | 100282 (14), archive puis exfiltration HTTP | vrai positif, gravité haute | preuve réseau absente, Script Block Logging, bruit 61618 |
| [02](ticket-02-tache-system-100271.md) | 100271 (12), tâche planifiée en SYSTEM | vrai positif, gravité haute ; tâche créée, lancée, supprimée en 4 s | corrélation 4698 → 4699, `auditpol /set`, bruit 61618 |
