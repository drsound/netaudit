# netaudit — Tool di diagnostica e gestione switch Aruba

## Dipendenze

```bash
pip install netmiko pyyaml
```

## Configurazione switch

Editare `switches.yaml` per aggiungere/modificare switch:

```yaml
switches:
  centro_stella:
    host: 10.168.13.100
    user: admin
    password: sid1963fio
    model: "Aruba 2930M-24G"
    location: "R1 - Centro Stella"
  r2:
    host: 10.168.13.201
    user: admin
    password: ...
    model: "Aruba 2930F"
    location: "R2"
```

In alternativa si possono passare le credenziali direttamente:

```bash
python3 netaudit.py --host 10.168.13.100 --user admin --password SECRET vlans
```

## Struttura file

```
netaudit/
├── netaudit.py        # Entry point CLI
├── switches.yaml      # Inventario switch con credenziali
├── README.md
└── lib/
    ├── switch.py          # Classe Switch (sessione netmiko)
    ├── diagnostics.py     # Operazioni di lettura e analisi
    ├── modifications.py   # Operazioni di scrittura con safety
    └── nmap_parser.py     # Parser XML nmap (database inventario rete)
```

---

## Comandi di lettura

```bash
# Diagnosi completa: esegue tutti i comandi e salva report su file
# (diagnose_<hostname>_<timestamp>.txt nella directory corrente)
python3 netaudit.py --switch centro_stella diagnose

# Running config completa
python3 netaudit.py --switch centro_stella config

# Lista VLAN
python3 netaudit.py --switch centro_stella vlans

# Dettaglio VLAN specifica
python3 netaudit.py --switch centro_stella vlan 2

# Spanning Tree (output completo)
python3 netaudit.py --switch centro_stella stp

# Analisi STP con avvisi automatici (TC count elevato, porte blocking, root bridge)
python3 netaudit.py --switch centro_stella stp check

# Stato porte (interface brief)
python3 netaudit.py --switch centro_stella ports

# Nomi/commenti delle porte
python3 netaudit.py --switch centro_stella port-names
python3 netaudit.py --switch centro_stella port-names 2/24   # solo una porta

# Tabella MAC (filtrabile per porta e/o VLAN)
python3 netaudit.py --switch centro_stella macs
python3 netaudit.py --switch centro_stella macs --port 2/14
python3 netaudit.py --switch centro_stella macs --vlan 2
python3 netaudit.py --switch centro_stella macs --port 2/14 --vlan 2

# Vicini LLDP (topologia)
python3 netaudit.py --switch centro_stella neighbors

# Log di sistema
python3 netaudit.py --switch centro_stella logs
```

---

## Comandi di modifica

Ogni operazione di scrittura segue questo protocollo:
1. **Preview** — mostra i comandi che verranno eseguiti
2. **Conferma** — chiede `Confermare? [s/N]` (default No)
3. **Esecuzione** — invia i comandi allo switch in config mode
4. **Verifica** — rilegge la configurazione e mostra il risultato

Il salvataggio (`write memory`) è sempre un comando esplicito separato e non avviene mai automaticamente.

### VLAN

```bash
# Crea VLAN
python3 netaudit.py --switch centro_stella vlan create 99 NOME_VLAN

# Rinomina VLAN
python3 netaudit.py --switch centro_stella vlan rename 99 NUOVO_NOME

# Elimina VLAN
# (se ci sono porte attive, mostra un avviso prima di chiedere conferma)
python3 netaudit.py --switch centro_stella vlan delete 99
```

### Porte — assegnazione VLAN

```bash
# Imposta porta in access mode (untagged) su una VLAN
python3 netaudit.py --switch centro_stella port access 1/3 10

# Aggiungi porta come tagged su una VLAN
python3 netaudit.py --switch centro_stella port tag 2/A1 100

# Rimuovi porta da tagged su una VLAN
python3 netaudit.py --switch centro_stella port untag 2/A1 100
```

### Porte — nome/commento

```bash
# Imposta nome sulla porta
python3 netaudit.py --switch centro_stella port set-name 1/2 "AP_Aruba_Ufficio"

# Rimuovi nome dalla porta (stringa vuota)
python3 netaudit.py --switch centro_stella port set-name 1/2 ""
```

### Salvataggio

```bash
# Salva running-config in startup-config (write memory)
python3 netaudit.py --switch centro_stella save
```

---

## Database nmap

Per usare i comandi `inventory`, `port find` e l'arricchimento della tabella MAC, occorre un file XML generato da nmap.

### Comando nmap

```bash
sudo nmap -sS -sU \
  -p T:21,22,23,80,135,139,443,445,3389,5000,8080,8443,U:137,161,5353 \
  -O --osscan-guess -sV --version-light \
  --script=nbstat,smb-os-discovery,snmp-sysdescr,dns-service-discovery \
  -T4 --max-retries 2 \
  -oX nmap-output.xml \
  10.168.0.0/20
```

- Tempo stimato: ~26 min per una /20 con ~380 host
- Il file deve chiamarsi **`nmap-output.xml`** e trovarsi nella **directory corrente** da cui si lancia netaudit

In alternativa si può specificare il percorso esplicitamente:

```bash
python3 netaudit.py --nmap-db /path/to/scan.xml inventory
# oppure
export NETAUDIT_NMAP_DB=/path/to/scan.xml
```

---

## Inventario nmap

Comandi che usano il DB nmap senza connettersi agli switch:

```bash
# Tutti gli host attivi nel DB
python3 netaudit.py inventory

# Filtra per OS
python3 netaudit.py inventory --os win
python3 netaudit.py inventory --os linux
python3 netaudit.py inventory --os other      # OS non identificato

# Filtra per servizio aperto
python3 netaudit.py inventory --service ssh
python3 netaudit.py inventory --service snmp
python3 netaudit.py inventory --service microsoft-ds

# Scopri quali servizi sono presenti nel DB
python3 netaudit.py inventory --list-services

# Trova su quale porta dello switch è connesso un host (IP, hostname o MAC)
python3 netaudit.py --switch centro_stella port find 10.168.0.3
python3 netaudit.py --switch centro_stella port find DESKTOP-2G07OBV
python3 netaudit.py --switch centro_stella port find aa:bb:cc:dd:ee:ff

# Tabella MAC arricchita con hostname dal DB nmap
python3 netaudit.py --switch centro_stella macs
```

---

## Flag --yes (per automazione/LLM)

Bypassa la conferma interattiva. Utile per uso programmatico:

```bash
python3 netaudit.py --switch centro_stella --yes vlan create 99 TEST
python3 netaudit.py --switch centro_stella --yes port set-name 2/24 "Server-ESXi"
python3 netaudit.py --switch centro_stella --yes save
```

---

## Note operative

- Gli argomenti non validi vengono controllati **prima** di aprire la connessione SSH.
- La connessione SSH usa `netmiko` in modalità interattiva.
- Lo switch gestisce il banner HPE e la conferma `[y/n]` in modo trasparente.
- Il report `diagnose` include: versione, VLAN, porte, STP, LLDP, MAC table, log, running-config.
