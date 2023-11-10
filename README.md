# Packet-Sniffer

Packet Sniffer GUI: An advanced, real-time packet sniffing and network analysis tool built with Python. This application leverages the power of Scapy for packet capture and analysis, and PyQt for a robust and user-friendly graphical interface.

## Key Features:

- Unlimited Packet Capture: The application can capture unlimited network packets in real-time, providing a comprehensive view of network activity.
- Detailed Packet View: Each captured packet can be selected to view its detailed information, providing in-depth insights into the packet's structure and content.
- Packet Filtering: The application supports Berkeley Packet Filter (BPF) syntax for targeted packet capture, allowing users to focus on specific types of network packets.
- Real-time GUI Updates: The application's GUI is updated in real-time as packets are captured, providing a live feed of network activity.
- Threaded Packet Sniffing: Packet sniffing is performed in a separate thread to ensure the GUI remains responsive, even during heavy network activity.
