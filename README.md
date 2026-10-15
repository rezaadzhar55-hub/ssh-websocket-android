# SSH WebSocket Android

Klien Android untuk menghubungkan akun SSH pada VPS melalui transport WebSocket (WS/WSS). Aplikasi menjalankan proxy SOCKS5 **lokal di perangkat** pada `127.0.0.1:1080`; hanya aplikasi yang secara manual diarahkan memakai proxy tersebut yang meneruskan koneksi **TCP** melalui SSH.

## Yang tersedia

- Autentikasi SSH dengan username dan kata sandi.
- Transport SSH di dalam frame WebSocket biner, dengan payload HTTP Upgrade yang dapat disunting.
- TLS WSS dengan validasi sertifikat standar Android.
- Verifikasi host key SSH menggunakan pin fingerprint `SHA256:`. Host key yang belum dikenal atau berbeda **ditolak**.
- Profil termasuk kata sandi disimpan terenkripsi AES-GCM memakai Android Keystore.
- Proxy SOCKS5 loopback hanya mendukung `CONNECT` TCP, tanpa autentikasi proxy.

Aplikasi ini **bukan VPN**, tidak memasang `VpnService`, tidak merutekan semua koneksi telepon, dan tidak membawa UDP. Konfigurasi harus dilakukan pada aplikasi yang memang mendukung SOCKS5 di Android. Endpoint proxy hanya mendengarkan di loopback ponsel.

## Persyaratan VPS

VPS harus milik/berada dalam kewenangan Anda dan sudah memiliki:

1. `sshd` aktif dengan akun SSH yang valid dan autentikasi kata sandi diizinkan jika memakai mode ini.
2. `AllowTcpForwarding yes` (atau kebijakan sshd yang mengizinkan channel `direct-tcpip`).
3. Gateway WebSocket yang menerima HTTP Upgrade dan meneruskan **frame WebSocket biner sebagai byte stream TCP** ke layanan SSH. WebSocket biasa yang hanya menampilkan halaman web tidak cukup.
4. Firewall jaringan mengizinkan koneksi dari ponsel ke gateway; gateway dapat meneruskan ke port SSH.

Salah satu pola umum adalah gateway `websockify` di belakang reverse proxy TLS seperti Nginx, diarahkan ke `127.0.0.1:22`. Contoh konsep (sesuaikan distro, alamat, autentikasi, dan hardening VPS):

```bash
websockify 127.0.0.1:6080 127.0.0.1:22
```

Contoh lokasi Nginx untuk meneruskan upgrade ke layanan tersebut:

```nginx
location /ws {
    proxy_pass http://127.0.0.1:6080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 1h;
}
```

Gunakan sertifikat TLS valid untuk domain gateway, dan batasi akses gateway/firewall. Contoh di atas bukan konfigurasi siap-produksi universal.

## Konfigurasi aplikasi

1. Isi host dan port SSH VPS, username, serta kata sandi SSH.
2. Isi host dan port gateway WebSocket. Aktifkan TLS/WSS jika gateway menggunakan HTTPS (umumnya port 443).
3. Atur payload HTTP Upgrade. Payload awal bawaan:

   ```text
   GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: [key][crlf]Sec-WebSocket-Version: 13[crlf][crlf]
   ```

   Sesuaikan path, misalnya `/ws`, dan header `Host` dengan konfigurasi gateway. Token yang tersedia: `[host]`, `[port]`, `[ssh_host]`, `[key]`, `[crlf]` dan bentuk kurung kurawal `{host}`, `{port}`, `{ssh_host}`, `{key}`. `[key]` harus ada pada header `Sec-WebSocket-Key`; respons gateway harus sukses `101 Switching Protocols` dan memiliki `Sec-WebSocket-Accept` yang valid. Frame data setelah Upgrade harus biner.
4. Simpan fingerprint host key SSH tepercaya (lihat langkah berikut) lalu tekan **Hubungkan SSH**.
5. Atur aplikasi di ponsel yang mendukung SOCKS5 ke server `127.0.0.1`, port `1080`. Tidak semua aplikasi Android menyediakan pengaturan proxy SOCKS5.

### Mendapatkan fingerprint SSH dengan aman

Jangan otomatis mempercayai nilai yang baru diterima. Saat percobaan pertama, aplikasi menolak host yang belum dipin dan menampilkan fingerprint yang diamati. Bandingkan dengan nilai tepercaya dari konsol VPS/out-of-band, misalnya jalankan di VPS:

```bash
for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f" -E sha256; done
```

Masukkan nilai `SHA256:...` yang cocok dengan algoritme host key yang ditampilkan aplikasi, simpan, lalu coba lagi. Jika fingerprint berubah, hentikan dan selidiki sebelum mengganti pin. Fingerprint bersifat publik; kata sandi SSH jangan dibagikan.

## Build

Persyaratan: JDK 17+, Android SDK Platform 35, serta Android Build Tools.

```bash
ANDROID_HOME=/path/ke/android-sdk ./gradlew assembleDebug
```

APK debug: `app/build/outputs/apk/debug/app-debug.apk`.

## Batas uji

Build APK telah diperiksa. Koneksi langsung belum dapat diuji tanpa gateway WebSocket dan kredensial VPS pengguna. Aplikasi ini klien saja: tidak memasang atau mengubah konfigurasi server, firewall, akun SSH, maupun gateway.
