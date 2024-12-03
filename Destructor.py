import sys
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QLabel,
    QWidget,
    QMessageBox,
    QLineEdit,
    QSizePolicy,
    QSpacerItem,
)
from PyQt5.QtCore import Qt
from scapy.all import IP, TCP, sr1  # Importer Scapy ici

# Instructions d'installation :
# Pour installer Python 3 et PyQt5 :
# 
# Sur macOS :
# 1. Télécharger Python 3 depuis python.org
# 2. Installer PyQt5 via la commande : pip3 install PyQt5
# 3. Installer Scapy via la commande : pip3 install scapy
# 
# Sur Windows :
# 1. Télécharger Python 3 depuis python.org
# 2. Installer PyQt5 via la commande : pip install PyQt5
# 3. Installer Scapy via la commande : pip install scapy

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Destructor - Outil de Sécurité")
        self.setGeometry(100, 100, 400, 400)  # Dimensions initiales
        self.setStyleSheet("background-color: black;")  # Changer le fond en noir
        self.initUI()

    def initUI(self):
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout principal avec marges
        layout = QVBoxLayout()
        layout.setContentsMargins(50, 50, 50, 50)  # Marges de 50 pixels

        # Label en haut de la fenêtre
        header_label = QLabel("Destructor")
        header_label.setStyleSheet(
            "font-size: 30px; font-weight: bold; color: white; text-align: center;"
        )
        header_label.setAlignment(Qt.AlignCenter)  # Centrer le texte
        layout.addWidget(header_label)

        # Ajouter un espace flexible avant les boutons
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Champ pour l'adresse IP
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Adresse IP cible (ex: 192.168.1.1)")
        layout.addWidget(self.ip_input)

        # Champ pour les ports
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Ports à scanner (ex: 21,22,23,80,443)")
        layout.addWidget(self.ports_input)

        # Ajouter un espace flexible avant les boutons
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Bouton Brute Force
        btn_brute_force = QPushButton("Brute Force")
        btn_brute_force.setStyleSheet("background-color: gray; color: white;")
        btn_brute_force.clicked.connect(self.run_brute_force)
        layout.addWidget(btn_brute_force)

        # Ajouter un espace flexible entre les boutons
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Bouton ARP Poisoning
        btn_arp_poisoning = QPushButton("ARP Poisoning")
        btn_arp_poisoning.setStyleSheet("background-color: gray; color: white;")
        btn_arp_poisoning.clicked.connect(self.run_arp_poisoning)
        layout.addWidget(btn_arp_poisoning)

        # Ajouter un espace flexible entre les boutons
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Bouton Scan de Port
        btn_scan_ports = QPushButton("Scan de Port")
        btn_scan_ports.setStyleSheet("background-color: gray; color: white;")
        btn_scan_ports.clicked.connect(self.scan_ports)
        layout.addWidget(btn_scan_ports)

        # Ajouter un espace flexible entre les boutons
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Bouton DDoS
        btn_ddos = QPushButton("DDoS")
        btn_ddos.setStyleSheet("background-color: gray; color: white;")
        btn_ddos.clicked.connect(self.run_ddos)
        layout.addWidget(btn_ddos)

        # Ajouter un espace flexible entre les boutons
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Bouton Exécuter Tout
        btn_execute_all = QPushButton("Exécuter Tout")
        btn_execute_all.setStyleSheet("background-color: blue; color: white;")
        btn_execute_all.clicked.connect(self.execute_all)
        layout.addWidget(btn_execute_all)

        # Ajouter un espace flexible avant la mention
        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Mention en bas
        footer_label = QLabel("Made by TP, ES, LU")
        footer_label.setStyleSheet("color: white; text-align: center;")
        footer_label.setAlignment(Qt.AlignCenter)  # Centrer le texte
        layout.addWidget(footer_label)

        # Définir le layout au widget central
        central_widget.setLayout(layout)

    def scan_ports(self):
        target = self.ip_input.text()
        ports_input = self.ports_input.text()
        if not target or not ports_input:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP et des ports.")
            return

        ports = [int(port.strip()) for port in ports_input.split(",")]

        results = []
        for port in ports:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is not None:
                if resp.haslayer(TCP) and (resp[TCP].flags == "SA"):
                    results.append(f"Le port {port} est ouvert")
                elif resp.haslayer(TCP) and (resp[TCP].flags == "RA"):
                    results.append(f"Le port {port} est fermé")
                else:
                    results.append(f"Le port {port} réponse : inconnu")

        # Afficher les résultats
        QMessageBox.information(self, "Scan de Port", "\n".join(results) if results else "Aucun résultat.")

    def execute_all(self):
        self.run_brute_force()
        self.run_arp_poisoning()
        self.run_ddos()
        self.scan_ports()  # Ne pas oublier d'exécuter le scan de port

    def run_brute_force(self):
        QMessageBox.information(self, "Action", "Brute Force lancé !")

    def run_arp_poisoning(self):
        QMessageBox.information(self, "Action", "ARP Poisoning lancé !")

    def run_ddos(self):
        QMessageBox.information(self, "Action", "DDoS simulé !")

    def close_application(self):
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
