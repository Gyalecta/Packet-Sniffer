from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QPlainTextEdit, QComboBox, QStatusBar
from scapy.all import sniff, get_if_list
import sys
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QPlainTextEdit, QComboBox, QStatusBar
from scapy.all import sniff, get_if_list
import sys
import threading
import os

os.environ['XDG_RUNTIME_DIR'] = '/tmp'

class Sniffer(QWidget):
    """
    A class representing a packet sniffer GUI.

    Attributes:
    - trigger (pyqtSignal): A signal that has no arguments.
    - sniffing (bool): A flag indicating whether the sniffer is currently sniffing packets.
    - textbox (QPlainTextEdit): A widget for displaying captured packets.
    - label (QLabel): A label for the sniffer GUI.
    - sniffButton (QPushButton): A button for starting packet sniffing.
    - stopButton (QPushButton): A button for stopping packet sniffing.
    - clearButton (QPushButton): A button for clearing the textbox.
    - ifaceComboBox (QComboBox): A combo box for selecting the network interface to sniff on.
    - statusBar (QStatusBar): A status bar for displaying messages.
    """

    # Define a new signal called 'trigger' that has no arguments.
    trigger = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.sniffing = False
        self.initUI()
        # Connect the trigger signal to a slot.
        self.trigger.connect(self.update_gui)

    def initUI(self):
        """
        Initializes the sniffer GUI.
        """
        self.setStyleSheet("background-color: lightblue;")

        self.textbox = QPlainTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: white; color: black;")

        self.label = QLabel('Packet Sniffer', self)
        self.label.setAlignment(Qt.AlignCenter)

        self.sniffButton = QPushButton('Start Sniffing', self)
        self.sniffButton.clicked.connect(self.sniff_packets)
        self.sniffButton.setStyleSheet("background-color: green; color: white;")

        self.stopButton = QPushButton('Stop Sniffing', self)
        self.stopButton.clicked.connect(self.stop_sniffing)
        self.stopButton.setStyleSheet("background-color: red; color: white;")

        self.clearButton = QPushButton('Clear', self)
        self.clearButton.clicked.connect(self.textbox.clear)

        self.ifaceComboBox = QComboBox(self)
        self.ifaceComboBox.addItems(get_if_list())

        self.statusBar = QStatusBar(self)
        self.statusBar.showMessage('Ready')

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self.label)
        hbox.addStretch(1)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addWidget(self.ifaceComboBox)
        vbox.addWidget(self.sniffButton)
        vbox.addWidget(self.stopButton)
        vbox.addWidget(self.clearButton)
        vbox.addWidget(self.textbox)
        vbox.addWidget(self.statusBar)

        self.setLayout(vbox)

        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 800, 600)
        self.show()

    def sniff_packets(self):
        """
        Starts packet sniffing on the selected network interface.
        """
        if not self.sniffing:
            self.sniffing = True
            self.statusBar.showMessage('Sniffing...')
            self.textbox.clear()
            # Start the packet sniffing in a new thread.
            threading.Thread(target=self.sniff_thread).start()

    def stop_sniffing(self):
        """
        Stops packet sniffing.
        """
        if self.sniffing:
            self.sniffing = False
            self.statusBar.showMessage('Stopped')

    def sniff_thread(self):
        """
        A thread for packet sniffing.
        """
        sniff(prn=self.process_packet, iface=self.ifaceComboBox.currentText(), stop_filter=lambda p: not self.sniffing)

    def process_packet(self, packet):
        """
        Processes a captured packet.
        """
        self.textbox.appendPlainText(str(packet))

    def update_gui(self):
        """
        Updates the GUI.
        """
        pass
        self.clearButton.clicked.connect(self.textbox.clear)

        self.ifaceComboBox = QComboBox(self)
        self.ifaceComboBox.addItems(get_if_list())

        self.statusBar = QStatusBar(self)
        self.statusBar.showMessage('Ready')

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self.label)
        hbox.addStretch(1)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addWidget(self.ifaceComboBox)
        vbox.addWidget(self.sniffButton)
        vbox.addWidget(self.stopButton)
        vbox.addWidget(self.clearButton)
        vbox.addWidget(self.textbox)
        vbox.addWidget(self.statusBar)

        self.setLayout(vbox)

        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 800, 600)
        self.show()

    def sniff_packets(self):
        """
        Starts packet sniffing on the selected network interface.
        """
        if not self.sniffing:
            self.sniffing = True
            self.statusBar.showMessage('Sniffing...')
            self.textbox.clear()
            # Start the packet sniffing in a new thread.
            threading.Thread(target=self.sniff_thread).start()

    def stop_sniffing(self):
        """
        Stops packet sniffing.
        """
        if self.sniffing:
            self.sniffing = False
            self.statusBar.showMessage('Stopped')

    def sniff_thread(self):
        """
        A thread function for packet sniffing.
        """
        # Use Scapy's sniff() function to sniff packets.
        sniff(prn=self.process_packet, iface=self.ifaceComboBox.currentText(), stop_filter=lambda p: not self.sniffing)
    def process_packet(self, packet):
        """
        A function for processing a captured packet.

        Args:
        - packet: The captured packet.

        Emits:
        - trigger: A signal that triggers the update_gui() function.
        """
        # This function will be called for each captured packet.
        # We emit the trigger signal and pass the packet as an argument.
        if self.sniffing:
            self.trigger.emit(packet)

    def update_gui(self, packet):
        """
        Updates the GUI with the new packet information.

        Args:
        - packet: The captured packet.
        """
        # Update the GUI with the new packet information.
        self.textbox.appendPlainText(str(packet))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Sniffer()
    sys.exit(app.exec_())
