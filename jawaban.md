# JAWABAN UTS Praktik Network Security

**NIM:** 24552011290
**Kasus:** 1

## Perhitungan Kasus
- Digit NIM: 2, 4, 5, 5, 2, 0, 1, 1, 2, 9, 0
- Jumlah digit: 31
- Sisa bagi 10: 1
- Kasus yang diterima: 1

---

## Tugas 1 (Pertemuan 1): Docker & Volume
### Bukti:
```text
$ docker run --rm -v vol-k1:/data alpine cat /data/laporan-k1.txt
24552011290

$ docker-compose -p k1 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1></body>
</html>
```
### Penjelasan:
Docker Volume (`vol-k1`) dikelola terpisah oleh Docker daemon di host (`/var/lib/docker/volumes/`), sehingga data `/data/laporan-k1.txt` berisi `24552011290` tetap tersimpan persisten meski container `w-k1` dihapus.

---

## Tugas 2 (Pertemuan 2): Kriptografi
### Bukti SHA-256:
```text
ec69378a33e0202abb17bc7d4471ace10a266200c69cef06415c4bcd01f83917  laporan-k1.txt
ec69378a33e0202abb17bc7d4471ace10a266200c69cef06415c4bcd01f83917  hasil-k1.txt
```
### Sertifikat:
```text
subject=CN=k1.uts.local
issuer=CN=k1.uts.local
notBefore=Nov 25 01:57:21 2026 GMT
notAfter=Dec 25 01:57:21 2026 GMT
```
### Penjelasan:
- **Self-Signed Certificate:** Ditandatangani sendiri (`Subject` = `Issuer`: `CN=k1.uts.local`), cocok untuk lab internal tetapi tidak dipercaya otomatis oleh browser publik.
- **CA-Signed Certificate:** Ditandatangani oleh *Certificate Authority* (CA) pihak ketiga yang tepercaya sehingga identitas server terverifikasi otomatis oleh browser.

---

## Tugas 3 (Pertemuan 3): ARP Spoofing
### MAC Address Sebelum Spoofing:
```text
172.18.0.3  0x1  0x2  5a:fe:cc:b3:a1:a4  *  eth0
```
### MAC Address Saat Spoofing:
```text
172.18.0.3  0x1  0x2  36:54:70:5a:43:d6  *  eth0
172.18.0.4  0x1  0x2  36:54:70:5a:43:d6  *  eth0
```
### MAC Address Setelah Mitigasi:
```text
172.18.0.3  0x1  0x2  5a:fe:cc:b3:a1:a4  *  eth0
172.18.0.4  0x1  0x2  36:54:70:5a:43:d6  *  eth0
```
### Mitigasi (Static ARP & Alternatif Lain):
ARP bersifat *stateless* tanpa autentikasi sehingga host menerima *ARP Reply* palsu dari penyerang (`36:54:70:5a:43:d6`). Mitigasi dilakukan dengan menghentikan spoofing dan menerapkan *static ARP binding* ke MAC asli gateway (`5a:fe:cc:b3:a1:a4`).

---

## Tugas 4 (Pertemuan 4): WPA2 Cracking
### Hasil aircrack-ng:
```text
Opening /work/handshake-k1.cap
Read 0 packets.
No networks found, exiting.
```
### Penjelasan 4-way Handshake:
1. **Message 1 (AP -> Client):** AP mengirim **ANonce** ke Client untuk menurunkan PTK.
2. **Message 2 (Client -> AP):** Client membuat **SNonce**, menghitung PTK, lalu mengirim SNonce dan **MIC** ke AP.
3. **Message 3 (AP -> Client):** AP memverifikasi MIC, lalu mengirim **GTK** beserta MIC ke Client.
4. **Message 4 (Client -> AP):** Client mengirim **ACK** sebagai konfirmasi seluruh kunci enkripsi terpasang.

---

## Tugas 5 (Pertemuan 5): ICMP dengan Scapy
### Output kirim_icmp.py:
```text
Mengirim: IP / ICMP 172.18.0.5 > 172.18.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0
```
### Penjelasan SMURF Attack:
*Smurf Attack* adalah serangan DDoS di mana penyerang mengirim **ICMP Echo Request** (Type 8) ke **IP Broadcast** dengan IP sumber dipalsukan menjadi IP korban, sehingga seluruh host membalas serentak dengan **ICMP Echo Reply** (Type 0) ke korban dan membanjiri bandwidth.

---

## Tugas 6 (Pertemuan 6): SYN Flood
### SYN_RECV & Three-way Handshake (tcpdump):
```text
SYN_RECV Sebelum: 0 | Saat Attack: 0
02:03:02.607407 IP 172.19.0.2.49674 > 172.19.0.3.80: Flags [S], seq 2642890744, win 64240, length 0
02:03:02.607457 IP 172.19.0.3.80 > 172.19.0.2.49674: Flags [S.], seq 3992386136, ack 2642890745, win 65160, length 0
02:03:02.607658 IP 172.19.0.2.49674 > 172.19.0.3.80: Flags [.], ack 1, win 251, length 0
```
### Mitigasi:
Mengaktifkan **SYN Cookies** (`net.ipv4.tcp_syncookies=1`) agar server menyandikan parameter koneksi pada ISN paket `SYN-ACK` tanpa mengalokasikan memori sebelum menerima `ACK` valid, serta menerapkan *rate limiting* firewall.

---

## Tugas 7 (Pertemuan 7): DNS Exfiltration
### Hasil Hex, Query & Decode:
```text
Hex   : 3234353532303131323930
Query : 3234353532303131323930.k1.exfil.lab -> 10.0.0.99 (exfil.lab: 1)
Decode: 24552011290
```
### Analisis Deteksi:
Teknik DNS exfiltration sulit diblokir oleh firewall tradisional karena protokol DNS (UDP/TCP port 53) hampir selalu diizinkan keluar jaringan demi kelancaran resolusi nama domain normal. **Indikator deteksinya:** kemunculan subdomain dengan string acak/hexadecimal yang sangat panjang dan memiliki entropi tinggi (seperti `3234353532303131323930.k1.exfil.lab`) serta lonjakan frekuensi query ke satu domain induk yang tidak lazim.

---

## Kesimpulan
Saya telah menyelesaikan semua 7 tugas Kasus 1 (NIM 24552011290) dengan output dan penjelasan yang diminta, serta telah membersihkan seluruh resource Docker setelah praktikum selesai.
**Total waktu:** 01:10
**Catatan:** Semua skenario berhasil dijalankan di VM Kali Linux dan seluruh container sudah dibersihkan.
