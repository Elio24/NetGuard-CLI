# 🎓 Guide de Préparation aux Entretiens Techniques — NetGuard-CLI

Ce document est conçu pour **Elio Fabrizio**. Il regroupe toutes les explications techniques, l'architecture du projet et les réponses aux questions pièges des recruteurs et ingénieurs en entretien d'embauche (Alternance Cybersécurité & Réseaux).

---

## 1. Fiche d'Identité du Projet (pitch de 30 secondes)

> *"Pour mettre en pratique mes compétences en protocoles réseaux (CCNA) et en développement Python, j'ai conçu **NetGuard-CLI**, un système de détection d'intrusions réseau (NIDS) en ligne de commande. Il capture et découpe les paquets (Ethernet, IP, TCP/UDP/ARP), et utilise des algorithmes de fenêtres glissantes (sliding window) pour détecter en temps réel des attaques courantes comme les scans de ports, le SYN Flood, le poisoning ARP et le tunneling DNS."*

---

## 2. Architecture Globale du Code

Le projet suit une **architecture modulaire découplée** pour respecter la séparation des responsabilités (Single Responsibility Principle) :

```
NetGuard-CLI/
├── netguard/
│   ├── packet_parser.py   # Couche 1 : Décodage binaire & structuration des trames
│   ├── analyzer.py        # Couche 2 : Moteur de détection comportementale (IDS)
│   ├── logger.py          # Couche 3 : Persistance des incidents (JSON & Text Reports)
│   ├── ui.py              # Couche 4 : Interface CLI dynamique (Rich Engine)
│   └── main.py            # Orchestrateur CLI (Live, PCAP & Simulation)
└── tests/                 # Tests unitaires automatisés (unittest)
```

---

## 3. Explication des Algorithmes de Détection (Le cœur technique)

### A. Détection du Scan de Ports (Port Scanning)
* **Principe** : Un attaquant (ex: Nmap) envoie des paquets TCP SYN ou UDP vers plein de ports différents d'une même victime pour découvrir les services ouverts.
* **Comment ton code le détecte (`_check_port_scan`)** :
  * Pour chaque IP source, on conserve un historique des paquets sous forme de file à double entrée (`collections.deque`) contenant `(timestamp, dst_port)`.
  * On nettoie les entrées plus anciennes que la **fenêtre glissante** (ex: 10 secondes).
  * On compte le nombre de ports **uniques** cibles. Si `len(unique_ports) >= 15`, une alerte `PORT_SCAN` est levée.

### B. Détection du SYN Flood (Attaque par Déni de Service - DoS)
* **Principe** : Dans le handshaking TCP à 3 voies (*3-way handshake* : SYN $\rightarrow$ SYN-ACK $\rightarrow$ ACK), l'attaquant envoie des milliers de paquets `SYN` sans jamais répondre avec le `ACK` final, ce qui sature la table de connexions du serveur (half-open connections).
* **Comment ton code le détecte (`_check_syn_flood`)** :
  * On filtre les paquets où le drapeau TCP `SYN == True` et `ACK == False`.
  * Si la fréquence de ces paquets dépasse un seuil (ex: 30 paquets SYN en moins de 5 secondes), une alerte `CRITICAL` `SYN_FLOOD` est générée.

### C. Détection du Poisoning ARP (ARP Spoofing / MITM)
* **Principe** : Le protocole ARP n'a pas d'authentification native. Un attaquant peut envoyer de fausses réponses ARP (*Gratuitous ARP*) pour associer son adresse MAC à l'adresse IP de la passerelle/routeur (Man-In-The-Middle).
* **Comment ton code le détecte (`_check_arp_spoofing`)** :
  * Le programme maintient une table de correspondance dynamique `IP -> MAC` (`_ip_mac_table`).
  * Si une trame ARP annonce une adresse MAC différente pour une IP déjà connue dans la table, NetGuard déclenche immédiatement une alerte `ARP_SPOOF`.

### D. Détection d'Anomalie DNS (DNS Tunneling)
* **Principe** : Des malwares utilisent les requêtes DNS pour exfiltrer des données ou contourner les pare-feux en encodant des données dans les sous-domaines (`data-chunk-xyz.attacker.com`).
* **Comment ton code le détecte (`_check_dns_anomaly`)** :
  * Analyse de la longueur du nom de domaine (`dns_query`). Si la taille dépasse 60 caractères, une alerte `DNS_ANOMALY` est relevée.

---

## 4. FAQ / Questions Récurrentes des Recruteurs en Entretien

### ❓ Question 1 : *"Pourquoi avoir utilisé Scapy / Sockets bruts au lieu de Wireshark directement ?"*
> **Réponse** : *"Wireshark est un excellent outil d'analyse visuelle et d'investigation post-mortem (DFIR), mais il ne permet pas d'automatiser un moteur de détection personnalisé ou de réagir dynamiquement à un incident. En codant NetGuard-CLI, je voulais comprendre exactement comment sont parsés les paquets au niveau octet et comment écrire des règles métier d'alerte."*

### ❓ Question 2 : *"Comment ton outil gère-t-il les performances sur un réseau à très fort trafic (10 Gbps) ?"*
> **Réponse** : *"NetGuard-CLI est un prototype écrit en Python avec une approche mono-threadée et des structures de données optimisées en $O(1)$ (`deque`, `hashmap`). Sur un trafic de production très haut débit, Python atteindrait la limite du GIL (Global Interpreter Lock). Dans un environnement industriel, on migrerait le moteur de capture vers C/C++ ou Rust avec DPDK (Data Plane Development Kit) ou eBPF au niveau du noyau Linux, et on utiliserait Python pour l'orchestration et le reporting."*

### ❓ Question 3 : *"Comment gères-tu les faux positifs (ex: un serveur web qui ouvre beaucoup de connexions légitimes) ?"*
> **Réponse** : *"C'est le défi principal des NIDS basés sur des seuils ! Dans NetGuard-CLI, les seuils sont configurables à l'initialisation (`TrafficAnalyzer`). Pour réduire les faux positifs dans la vraie vie, on combinerait cette analyse comportementale basée sur les seuils avec une whitelist d'IPs de confiance et de l'analyse basées sur des signatures (comme Snort/Suricata)."*

### ❓ Question 4 : *"Comment as-tu testé ton code ?"*
> **Réponse** : *"J'ai écrit une suite de tests unitaires automatisés avec `unittest` pour valider le découpage des paquets et la détection d'anomalies. De plus, j'ai intégré un mode simulation (`--simulate`) qui génère du trafic synthétique mixant du trafic légitime et des attaques injectées, ce qui permet de tester l'application sans droits d'administration."*

---

## 5. Lexique Technique à Maîtriser Absolument

* **Sliding Window (Fenêtre glissante)** : Méthode permettant d'analyser le comportement d'une IP sur une plage temporelle fixe (ex: les 10 dernières secondes) en supprimant au fur et à mesure les événements trop anciens.
* **TCP Flags** :
  * **SYN** (Synchronize) : Demande d'ouverture de connexion TCP.
  * **ACK** (Acknowledge) : Accusé de réception.
  * **FIN** (Finish) : Demande de fermeture propre.
  * **RST** (Reset) : Interruption immédiate d'une connexion.
* **NIDS vs HIDS** :
  * **NIDS** (Network-based IDS) : Analyse le trafic circulant sur le réseau (ex: NetGuard-CLI, Snort).
  * **HIDS** (Host-based IDS) : Surveille les événements d'une seule machine (ex: logs, registres, processus).
