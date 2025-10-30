# 🔐 Basic Network Sniffer using Python (Scapy)

### 💡 About the Project
This project is developed as part of my **CodeAlpha Cybersecurity Internship**.  
It focuses on understanding how data flows through a network by capturing and analyzing live packets using the **Scapy** library in Python.

The tool captures packets in real time, displays useful information such as **source and destination IPs**, **protocols (TCP, UDP, ICMP, ARP)**, and saves all captured packets into a `.pcap` file for detailed analysis using **Wireshark**.

---

### ⚙️ Features
- 📡 Capture real-time network traffic  
- 🧩 Display IP addresses, ports, and protocol information  
- 🗃️ Save captured packets in `.pcap` format  
- 🧠 Understand network communication and protocol structure  
- 💻 Fully compatible with **Kali Linux** (VirtualBox supported)

---

### 🧰 Technologies Used
- **Python 3**
- **Scapy** library
- **Wireshark** (for analysis)
- **Kali Linux**

---

### 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/Kavin-cse/CodeAlpha_NetworkSniffer.git
   cd CodeAlpha_NetworkSniffer
2. Install Scapy (if not already installed):
   ```bash
   sudo apt install python3-pip
   pip install scapy
3. Run the sniffer:
   ```bash
   sudo python3 sniffer_scapy.py
4. Stop the capture with Ctrl + C.
   The captured packets will be saved as:
   ```bash
   captured_packets.pcap
5. Open this file in Wireshark for detailed analysis.

---

### 🧠 Learning Outcomes

- Understood how network packets are structured

- Gained hands-on experience in packet sniffing using Scapy

- Learned to analyze packet data in Wireshark

- Improved understanding of network protocols (TCP, UDP, ICMP, ARP)

---

### 🧑‍💻 Author

**Kavin M**

**Cybersecurity Intern — CodeAlpha**
