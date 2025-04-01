# 🧪 TCP Sniffer in C

Un semplice **sniffer TCP scritto in C** che intercetta pacchetti TCP in ingresso sulla macchina locale, con supporto al filtraggio per porta e salvataggio dei risultati in **formato CSV**, completo di **timestamp per ogni pacchetto**.

---

## ✨ Funzionalità principali

- 🔍 **Filtro per porta TCP**, IP sorgente e IP destinazione (opzionali via `-p`, `-s`, `-d`)
- 📄 **Salvataggio CSV** dei pacchetti intercettati
- ⏱️ **Timestamp per ogni pacchetto**
- 📶 **Hostname** risolti per ogni IP
- 🎨 Visualizzazione del **payload TCP** in esadecimale (fino a 32 byte)
- 🚩 Interruzione pulita via `Ctrl+C` con richiesta di conferma per il salvataggio

---

## 🚀 Come funziona

1. Apre una **socket RAW IPv4** per intercettare pacchetti TCP in arrivo alla macchina locale
2. Mostra a terminale l'orario, IP e hostname sorgente/destinazione, porta e tipo pacchetto
3. Alla chiusura (Ctrl+C), chiede se vuoi esportare il log
4. Se confermi (`y`), crea un file `log.csv` con tutti i pacchetti intercettati

> ⚠️ **Nota importante**: lo sniffer intercetta solo pacchetti **diretti alla macchina locale**. Non può vedere il traffico di altri dispositivi sulla rete (a differenza di Wireshark), perché usa una socket `AF_INET`. Per sniffare tutto il traffico in rete, servirebbe usare `AF_PACKET` o `libpcap` con modalità promiscua.

---

## ✅ Requisiti

- Linux (obbligatorio)
- Compilatore `gcc`
- Permessi root per usare socket RAW

---

## 🛠️ Compilazione

Nella cartella `C-version/`, esegui:

```bash
make
```

---

## ▶️ Esecuzione

### Sniffing su **tutte le porte TCP**

```bash
sudo ./sniffer
```

### Sniffing **solo su una porta** (es. porta 80)

```bash
sudo ./sniffer -p 80
```

### Sniffing con **filtro su IP sorgente**

```bash
sudo ./sniffer -s 192.168.1.10
```

### Sniffing con **filtro su IP destinazione**

```bash
sudo ./sniffer -d 8.8.8.8
```

---

## 📂 Esempio di file CSV generato

```csv
timestamp,src_ip,src_hostname,src_port,dst_ip,dst_hostname,dst_port,payload_hex
2025-04-01 21:10:32,192.168.1.2,router.local,443,10.0.0.5,laptop.local,55012,4a6f686e
2025-04-01 21:10:33,172.217.16.14,google.com,443,192.168.1.2,router.local,33512,48656c6c6f
```

---

## 🔐 Permessi

Serve eseguire con `sudo` oppure abilitare il binario:

```bash
sudo setcap cap_net_raw=eip ./sniffer
```

---

## 🛋️ Pulizia

```bash
make clean
```

---

## 📊 Idee per miglioramenti futuri

- [ ] Aggiunta di supporto per UDP/ICMP
- [ ] Esportazione alternativa in JSON o XML
- [ ] Modalità promiscua via AF_PACKET
- [ ] Interfaccia interattiva con ncurses o Qt

---

Creato da **Emiliano** 🫠
