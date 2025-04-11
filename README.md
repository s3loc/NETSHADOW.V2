# NETSHADOW.V2

A comprehensive network security and analysis toolkit


🌟 Features
Network Analysis

    WiFi network scanning

    Port scanning with service detection

    Network device discovery

    Bandwidth monitoring

    Packet sniffing

Security Tools

    Vulnerability scanning

    SQL injection testing

    Bluetooth device scanning

    ARP spoofing detection

    VPN connection detection

Utilities

    IP geolocation

    DNS lookup

    Data encryption/decryption

    Network traffic analysis



python main.py

Follow the interactive menu to select tools. Key options:
Option	Description	Option	Description
1	Scan WiFi Networks	2	List Network Interfaces
3	Port Scan	4	List Network IPs
7	Vulnerability Scan	8	List VPN Connections
13	DDoS Attack (⚠️)	14	Email Spam (⚠️)
19	Data Analyzer	20	DNS Lookup
0	Exit	100	Help
⚙️ Configuration

Edit the Config class in main.py:
python
Copy

@dataclass
class Config:

    TOR_PASSWORD: str = "your_tor_password"
    SMTP_SERVER: str = "smtp.gmail.com"
    EMAIL_FROM: str = "your_email@gmail.com"
    EMAIL_PASSWORD: str = "your_email_password"
    AES_KEY: str = "supersecretkey1234567890"

⚠️ Warning

This toolkit contains powerful network analysis tools. Some features may:

    Be illegal without proper authorization

    Cause service disruptions

    Violate terms of service

Use only on networks you own or have explicit permission to test.


MIT License (Consider your actual license)



========================================================================================================================
NETSHADOW.V2 

Kapsamlı bir ağ güvenlik ve analiz araç seti


🌟 Özellikler
Ağ Analiz

    WiFi ağ tarama

    Servis tespitli port tarama

    Ağ cihaz keşfi

    Bant genişliği izleme

    Paket dinleme

Güvenlik Araçları

    Zafiyet tarama

    SQL injection testi

    Bluetooth cihaz tarama

    ARP spoofing tespiti

    VPN bağlantı tespiti

Yardımcı Araçlar

    IP konum bulma

    DNS sorgulama

    Veri şifreleme/çözme

    Ağ trafik analizi





Etkileşimli menüden araçları seçin. Temel seçenekler:


Seçenek	Açıklama	Seçenek	Açıklama

1	WiFi Ağlarını Tara	2	Ağ Arayüzlerini Listele
3	Port Taraması	4	Ağ IP'lerini Listele
7	Zafiyet Taraması	8	VPN Bağlantılarını Listele
13	DDoS Saldırısı (⚠️)	14	Email Spam (⚠️)
19	Veri Analizörü	20	DNS Sorgulama
0	Çıkış	100	Yardım
⚙️ Yapılandırma

main.py içindeki Config sınıfını düzenleyin:
python
Copy

@dataclass
class Config:

    TOR_PASSWORD: str = "tor_sifreniz"
    SMTP_SERVER: str = "smtp.gmail.com"
    EMAIL_FROM: str = "emailiniz@gmail.com"
    EMAIL_PASSWORD: str = "email_sifreniz"
    AES_KEY: str = "gizlianahtar1234567890"

⚠️ Uyarı

Bu araç seti güçlü ağ analiz araçları içerir. Bazı özellikler:

    Yetkisiz kullanımda yasa dışı olabilir

    Hizmet kesintilerine yol açabilir

    Kullanım şartlarını ihlal edebilir

Yalnızca sahibi olduğunuz ağlarda veya test izni olan sistemlerde kullanın.

