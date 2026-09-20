# KJK-DGA-Kel3-Week3

| No | Nama | NRP |
|---|---|---|
| 1 | Hasheemi Rafsanjeni | 5027251015 |
| 2 | Rido Patra Yudhistira Edwin | 5027251120 |
| 3 | Mahrinza Redouane Zakariyah | 5027251074 |


## 1. Study Case

**Domain Generation Algorithm (DGA)** adalah teknik malware untuk menemukan server command-and-control (C2) tanpa menanam alamat tetap di dalam kodenya. Malware membangkitkan ratusan sampai ribuan nama domain acak secara otomatis, lalu mencoba meng-query-nya satu per satu. Penyerang cukup mendaftarkan sebagian kecil domain dari daftar itu untuk dijadikan server C2. Dengan cara ini, memblokir satu domain tidak berguna karena besok daftarnya berganti.

Karena sebagian besar domain tidak terdaftar, jejaknya di jaringan mudah dikenali:

- banyak respons **NXDOMAIN** (domain tidak ada) dari satu host
- nama domain acak, panjang, dan tidak bermakna
- TLD yang bervariasi dan laju query yang teratur
- sesekali satu domain berhasil resolve, lalu host langsung menghubungi IP tersebut

**Kasus yang dianalisis:** capture 5.945 paket (sekitar 96 menit) dari sebuah komputer Windows `10.0.2.103` yang diduga terinfeksi malware. Tugasnya: mencari indikasi serangan dan menentukan jenisnya.

---

## 2. Analisis pcap

<img width="1914" height="951" alt="0" src="https://github.com/user-attachments/assets/4216ef39-9fd7-4de1-82e7-6db72c95563f" />

### 2.1 Gambaran umum

Hampir seluruh traffic adalah UDP (5.403 dari 5.945 paket), dan sebagian besar berupa DNS antara host `10.0.2.103` dan resolver `8.8.8.8`. Ini janggal untuk satu komputer dalam 96 menit, sehingga analisis difokuskan ke DNS.

### 2.2 Banjir NXDOMAIN

| Metrik | Nilai |
|---|---|
| Total query DNS | 2.673 (semua dari 10.0.2.103) |
| Respons NXDOMAIN | **2.654 dari 2.668 (99,5%)** |

**Filter:** `dns.flags.rcode == 3`  |  **Menu:** `Statistics > DNS`

<img width="1918" height="961" alt="1" src="https://github.com/user-attachments/assets/feea2aa7-b14f-4b11-ba06-70d71198067d" />

### 2.3 Nama domain acak

Contoh nama yang di-query:

```
tctceagiqcpbpjzpaqnjrgireuwy.com
qgvfyivyduotsfqdxstwljvoirzl.net
xgqzxefuhpjnlhicizpkrxcu.org
uwxcovqkkfdutrsbadqpfnfgm.biz
cmdfatwyppvgijdrwnbsocefyugyt.ru
```

| Ciri | Hasil |
|---|---|
| Panjang label | 18 sampai 32 karakter (median 25) |
| Entropi rata-rata | 3,88 bit (`google` sekitar 1,92) |
| Rasio huruf vokal | sekitar 19% (bahasa Inggris sekitar 38%) |
| TLD | com, net, org, biz, info, ru bergantian |

**Filter:** `dns.qry.name.len > 20`. Tambahkan kolom `dns.qry.name` agar daftar domain terlihat jelas.

<img width="1918" height="961" alt="2" src="https://github.com/user-attachments/assets/ced19689-62d9-4788-a45f-c4b2ff28abdd" />

### 2.4 Pola waktu

Saat aktif, query berjalan stabil sekitar 40 per menit (interval median 1,5 detik). Aktivitasnya terbagi menjadi tiga gelombang yang dipisah jeda sekitar 12 menit (detik ke-1.751 sampai 2.478, dan 3.993 sampai 4.729). Gelombang kedua berisi tepat 1.000 query, artinya malware menelusuri daftar 1.000 domain sampai habis, berhenti sebentar, lalu mengulang daftar yang sama. Satu siklus penuh sekitar 37 menit. Gelombang ketiga terpotong karena capture berakhir.

**Menu:** `Statistics > I/O Graph` dengan filter `dns.flags.rcode == 3`

<img width="850" height="683" alt="3" src="https://github.com/user-attachments/assets/f9515a83-1b20-470b-8416-9afd6e7e55fd" />


### 2.5 Domain yang berhasil resolve dan koneksi C2

Dari sekitar seribu domain, hanya dua yang berhasil resolve. Setelah itu host langsung mengirim HTTP `GET /` ke IP-nya:

| Domain | IP | Respons |
|---|---|---|
| `pcqampjtctmbtobzleivojvzr.info` | 69.195.129.70 | `200 OK`, kosong |
| `bexhlzkjobugdeukxpknztytl.info` | 166.78.144.80 | `200 OK`, header **`X-Sinkhole: malware-sinkhole`** |

Header `X-Sinkhole` menandakan server kedua adalah **sinkhole** milik pihak keamanan, sehingga komunikasi ini tidak sampai ke penyerang. Meski begitu, ini membuktikan host sedang mencoba menghubungi infrastruktur botnet.

**Filter:** `dns.flags.response == 1 && dns.flags.rcode == 0`, `ip.addr == 166.78.144.80`, `http contains "X-Sinkhole"` (lalu `Follow > HTTP Stream`)

<img width="1919" height="958" alt="4" src="https://github.com/user-attachments/assets/ed18203c-de35-4d5e-b792-867d95ed9545" />

<img width="1622" height="571" alt="5_2" src="https://github.com/user-attachments/assets/1215c488-c594-49cd-9601-d655e0c8e3a7" />

### 2.6 Bukan salah deteksi

Salah ketik pengguna tidak menghasilkan seribu nama acak yang berulang. DNS tunneling tidak cocok karena tipe query hanya A dan setiap nama adalah domain berbeda. Flood tidak cocok karena lajunya hanya sekitar 40 query per menit dari satu host.

---

## 3. Kesimpulan

1. **Jenis serangan:** infeksi malware botnet yang memakai **DGA** untuk mencari server C2.
2. **Bukti utama:** 99,5% respons NXDOMAIN, sekitar 1.000 nama acak berentropi tinggi, enam TLD bergantian, laju konstan, dan daftar yang berulang tiap sekitar 37 menit.
3. **Bukti C2:** dua domain berhasil resolve dan langsung diikuti koneksi HTTP; salah satunya adalah sinkhole.
4. **Keterbatasan:** analisis hanya dari traffic, jadi family malware tidak dapat dipastikan.
5. **Rekomendasi:** isolasi host `10.0.2.103`, lakukan pemindaian malware atau reimage, dan buat deteksi berbasis perilaku (rasio NXDOMAIN tinggi dan nama berentropi tinggi) karena daftar blokir statis tidak efektif melawan DGA.
