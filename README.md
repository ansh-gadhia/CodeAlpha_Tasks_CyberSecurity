# 🕵️‍♂️ CodeAlpha Network Sniffer

A fun, colorful, and educational **Network Packet Sniffer** built in Python!  
Capture, analyze, and log network packets in real time with a beautiful, user-friendly terminal interface.

---

## 🚀 Features

- **Live Packet Capture:** See packets as they traverse your network interface.
- **Protocol Support:** TCP, UDP, ICMP, and more.
- **Colorful Output:** Distinct colors for different protocols and warnings.
- **Live Statistics:** Real-time protocol counters after each packet.
- **Interface Selection:** Easily choose which network interface to sniff (Linux).
- **Protocol Filtering:** Capture only TCP, UDP, or ICMP packets if desired.
- **Packet Logging:** Optionally log packet summaries to a CSV file.
- **Hex & ASCII Payload View:** See both hex and readable payloads.
- **Cross-Platform:** Works on Linux and Windows (with admin/root privileges).
- **Educational:** Well-commented and easy to extend for learning or research.

---

## 📸 Demo

![screenshot](https://github.com/ansh-gadhia/CodeAlpha_Tasks_CyberSecurity/blob/main/Network%20Sniffer%20Working.png)

---

## 🛠️ Usage

### 1. **Install Requirements**

No external dependencies required!  
Just make sure you have Python 3.x.

### 2. **Run the Sniffer**

```bash
# Linux (run as root)
sudo python3 "CodeAlpha_Basic Network Sniffer.py" [options]

# Windows (run as Administrator)
python "Basic Network Sniffer.py" [options]
```

### 3. **Options**

| Option            | Description                                      |
|-------------------|--------------------------------------------------|
| `-c`, `--count`   | Number of packets to capture (default: unlimited)|
| `-p`, `--protocol`| Filter by protocol: `tcp`, `udp`, or `icmp`      |
| `-i`, `--interface`| Network interface to sniff (Linux only)         |
| `-l`, `--log`     | Log captured packets to a CSV file               |

**Examples:**

```bash
# Capture 10 TCP packets on eth0 and log to packets.csv
sudo python3 "CodeAlpha_Basic Network Sniffer.py" -c 10 -p tcp -i eth0 -l packets.csv

# Capture all packets on default interface
sudo python3 "CodeAlpha_Basic Network Sniffer.py"
```

---

## ⚠️ Permissions

- **Linux:** Must run as `root` (use `sudo`).
- **Windows:** Must run as Administrator.

---

## 🧑‍💻 Code Structure

- **Colorful output** using ANSI codes.
- **Packet parsing** for Ethernet, IP, TCP, UDP, and ICMP.
- **Live stats** and optional CSV logging.
- **Modular design** for easy extension.

---

## 📚 Educational Use

This tool is designed for learning and research.  
**Do not use on networks you do not own or have permission to monitor.**

---

## ✨ Credits

- Developed by **Ansh Gadhia** for CodeAlpha Cybersecurity Internship 2025.
- Inspired by classic packet sniffers, but with a unique, modern, and colorful twist!

---

## 🤝 Contributing

Pull requests and suggestions are welcome!  
Feel free to fork and enhance this project.

---








