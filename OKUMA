🔐 Gelişmiş BHPNet (Backdoor Hackers' Python Network Tool)
Gelişmiş BHPNet, Python tabanlı, SSL destekli, komut çalıştırma, dosya yükleme ve uzak terminal erişimi sağlayabilen bir ağ aracıdır. Güvenlik amaçlı testler, penetrasyon denemeleri ve sistem yönetimi görevleri için geliştirilmiştir.

❗ Yalnızca eğitim ve yasal test ortamlarında kullanınız. Yetkisiz kullanım suç teşkil eder.

🚀 Özellikler
✅ SSL/TLS Desteği: Trafik şifreleme ile güvenli bağlantılar

🖥️ Uzak Terminal: Komut satırı erişimi ve kontrolü

📂 Dosya Yükleme: Hedefe güvenli dosya transferi

🔒 Komut Filtreleme (Beyaz Liste): Yetkisiz veya tehlikeli komutları engelleme

📑 Loglama: İsteğe bağlı olarak dosyaya ayrıntılı log kaydı

🎨 Renkli Konsol Çıktısı: Daha okunabilir ve şık çıktı (Windows ve Linux destekli)

🛡️ İstemci ve Sunucu Modu: Hem bağlantı kurabilir hem dinleyebilirsiniz

⚙️ Kurulum
Python 3.x yüklü olduğundan emin olun.

Gerekli modülleri yükleyin (bazıları Python ile gelir):

bash
Kopyala
Düzenle
pip install colorama
Eğer SSL sertifikalarınız yoksa, program ilk çalıştırmada otomatik olarak kendi kendine imzalı sertifika üretir (server.crt, server.key).

🧪 Kullanım
🔁 Dinleyici (Sunucu) Modu
bash
Kopyala
Düzenle
python bhpnet.py -l -p 4444 -c --ssl --verbose --log=server.log
📤 Dosya Yükleme
bash
Kopyala
Düzenle
python bhpnet.py -l -p 8888 -u=/tmp/incoming_file.txt --ssl
🧨 Komut Çalıştırma
bash
Kopyala
Düzenle
python bhpnet.py -l -p 9999 -e="ls -la" --ssl
⛓️ İstemci Modu
bash
Kopyala
Düzenle
echo "uname -a" | python bhpnet.py -t 127.0.0.1 -p 4444 --ssl
⚠️ Güvenlik Uyarıları
Bu araç sızma testleri ve CISO/sistem yöneticileri için geliştirilmiştir.

Üçüncü taraf sunuculara, sistemlere veya cihazlara izinsiz erişim kanunen yasaktır.

Komut beyaz liste filtresiyle sınırlı komut çalıştırmaya dikkat ediniz. Geliştirme sırasında filtre dışı tehlikeli komutlar engellenir.

📁 Dosya Yapısı
bash
Kopyala
Düzenle
bhpnet.py          → Ana betik
server.crt/key     → SSL sertifikaları (otomatik üretilir)
README.md          → Açıklama dosyası
