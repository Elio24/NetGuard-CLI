# NetGuard-CLI

Analyseur de trafic réseau et système de détection d'intrusions (NIDS) en ligne de commande.

Ce projet permet de capturer du trafic réseau (en direct ou via fichier `.pcap`), d'analyser la structure des paquets (Ethernet, IP, TCP, UDP, ARP, DNS) et de détecter automatiquement certains comportements malveillants ou anormaux en temps réel.

## Détections prises en charge

* **Scan de ports (Port Scanning)** : Détection d'IPs balayant un nombre élevé de ports dans une fenêtre temporelle restreinte.
* **SYN Flood (DoS)** : Identification des attaques TCP SYN flood par suivi des demandes de connexion sans ACK.
* **Poisoning ARP (ARP Spoofing)** : Détection des associations IP/MAC frauduleuses (tentatives de Man-In-The-Middle).
* **Anomalies DNS** : Repérage de requêtes DNS anormalement longues (potentiel tunneling DNS).

## Structure du projet

```
NetGuard-CLI/
├── netguard/
│   ├── main.py           # Entrée CLI (arguments, orchestrateur)
│   ├── packet_parser.py  # Decodage des paquets réseau (Scapy)
│   ├── analyzer.py       # Moteur de détection d'anomalies (Sliding window)
│   ├── ui.py             # Affichage terminal (Rich)
│   └── logger.py         # Export des alertes en JSON et rapport text
├── tests/
│   ├── test_parser.py    # Tests unitaires du parser
│   └── test_analyzer.py  # Tests unitaires du moteur de détection
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone https://github.com/Elio24/NetGuard-CLI.git
cd NetGuard-CLI

python -m venv .venv
source .venv/bin/activate  # Sur Windows : .venv\Scripts\activate

pip install -r requirements.txt
```

## Utilisation

### Mode simulation (sans droits admin)
Génère du trafic de démonstration avec injection d'attaques pour tester le moteur sans privilèges réseau :
```bash
python -m netguard.main --simulate
```

### Analyse d'un fichier PCAP
```bash
python -m netguard.main --pcap /chemin/vers/capture.pcap
```

### Capture en direct (requiert les privilèges root / Administrateur)
```bash
# Linux
sudo python3 -m netguard.main --interface eth0

# Windows (Invite Administrateur)
python -m netguard.main --interface "Wi-Fi"
```

## Tests

Pour exécuter la suite de tests unitaires :
```bash
python -m unittest discover -s tests
```
