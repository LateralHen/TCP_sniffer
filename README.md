# 🧪 TCP Sniffer in C

Questo è un semplice **sniffer TCP scritto in C** che intercetta pacchetti TCP in arrivo sulla macchina locale.

Supporta:

- 🔍 Filtro per porta (opzionale)
- 📄 Salvataggio dei pacchetti in formato CSV
- ⏱️ Timestamp di avvio e di interruzione dello sniffer
- 🧼 Pulizia automatica della memoria alla chiusura

---

## 🚀 Come funziona

Il programma:

1. Apre una **socket RAW** per intercettare pacchetti TCP in arrivo.
2. Mostra a schermo gli indirizzi IP e le porte coinvolte.
3. Alla chiusura (Ctrl+C), chiede all'utente se vuole salvare i risultati.
4. Se si conferma (`y`), i pacchetti vengono salvati in `log.csv` in formato leggibile e con **intestazione**.

---

## ✅ Requisiti

- Linux (con permessi `sudo`)
- Compilatore `gcc`

---

## 🛠️ Compilazione

All'interno della cartella `C-version/`, usa:

```bash# 🧪 TCP Sniffer in C

Un semplice **sniffer TCP scritto in C** che intercetta pacchetti TCP in ingresso sulla macchina locale, con supporto al filtraggio per porta e salvataggio dei risultati in **formato CSV**, completo di **timestamp di avvio e arresto**.

---

## ✨ Funzionalità principali

- 🔍 **Filtro per porta TCP** (opzionale via `-p <porta>`)
- 📄 **Salvataggio CSV** dei pacchetti intercettati
- ⏱️ **Timestamp leggibili** all'avvio e all'arresto dello sniffer
- 🚩 Interruzione pulita via `Ctrl+C` con richiesta di conferma per il salvataggio
- 💡 Funziona da terminale, interfaccia semplice

---

## 🚀 Come funziona

1. Apre una **socket RAW** per intercettare pacchetti TCP in arrivo
2. Stampa a terminale l'IP e la porta sorgente/destinazione di ogni pacchetto
3. Quando premi `Ctrl+C`, salva l'orario e chiede se vuoi esportare il log
4. Se confermi (`y`), crea un file `log.csv` con tutti i pacchetti intercettati e i relativi timestamp

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

Compila il file `main.c` e genera l'eseguibile `sniffer`.

---

## ▶️ Esecuzione

### Sniffing su **tutte le porte TCP**

```bash
sudo ./sniffer
```

### Sniffing **solo su una porta specifica** (es. porta 80):

```bash
sudo ./sniffer -p 80
```

Durante l'esecuzione vedrai in tempo reale qualcosa del genere:

```text
🔵 Sniffer avviato: 2025-04-01 21:10:32
[TCP] 192.168.1.2:443 --> 10.0.0.5:55012
[TCP] 172.217.16.14:443 --> 192.168.1.2:33512
^C
🔴 Sniffer terminato: 2025-04-01 21:12:01
Vuoi salvare i risultati in 'log.csv'? (y/n): y
Log salvato in 'log.csv'
```

---

## 📂 Esempio di file CSV generato

```csv
# Sniffer avviato: 2025-04-01 21:10:32
# Sniffer terminato: 2025-04-01 21:12:01
src_ip,src_port,dst_ip,dst_port
192.168.1.2,443,10.0.0.5,55012
172.217.16.14,443,192.168.1.2,33512
```

---

## 🔐 Note sui permessi

Per intercettare pacchetti con socket RAW, servono **permessi elevati**:

```bash
sudo ./sniffer
```

Oppure (per evitare `sudo` ogni volta):

```bash
sudo setcap cap_net_raw=eip ./sniffer
```

---

## 🛋️ Pulizia

Per rimuovere l'eseguibile:

```bash
make clean
```
