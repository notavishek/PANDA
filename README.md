# PANDA: Smart Alert System Simulation in OMNeT++

**PANDA** (Proactive Alert Network for Detection & Analysis) is a network simulation project designed to demonstrate a Smart Alert System built in **OMNeT++**. The system proactively monitors and analyzes a localized network environment to detect anomalies and issue alerts based on real-time traffic patterns and predefined thresholds.

---

## 🎯 Project Objective

> To develop and simulate a **Smart Alert System** in **OMNeT++** that proactively analyzes localized network environments to detect and flag abnormal or suspicious activity.

This includes:
- Packet-level monitoring
- Event-driven alerting
- Node-level fault simulation
- Dynamic response evaluation

---

## 🔧 Technologies Used

- **OMNeT++** (Version 6.0 or above)
- **INET Framework** for network modeling
- **C++** for custom module development
- **NED** for network architecture configuration

---

## 📁 Project Structure

```
PANDA/
├── src/
│   ├── package.ned
│   ├── PandaNetwork.ned          # Network definition
│   ├── AnomalyObserver.ned       # Module definition
│   ├── AnomalyObserver.h         # Header file
│   ├── AnomalyObserver.cc        # Implementation
│   └── omnetpp.ini              # Configuration
├── simulations/
│   ├── omnetpp.ini              # Alternative config location
│   └── network-config.xml       # IP configuration
└── results/                     # Output directory

```

---

## 🚀 Getting Started

### Prerequisites
- [OMNeT++ 6.0](https://omnetpp.org/download/) or higher
- INET Framework (imported and compiled in OMNeT++)

### Setup Instructions

1. **Clone the Repository**
```bash
git clone https://github.com/notavishek/PANDA.git
cd PANDA
```

2. **Open the Project in OMNeT++ IDE**
- Launch OMNeT++ IDE
- Import the `PANDA` project
- Make sure the INET Framework is correctly linked

3. **Build the Project**
- Right-click the project > **Build Project**

4. **Run the Simulation**
- Open `omnetpp.ini`
- Run with `TrafficDemo` as the active configuration

---

## 🔍 Key Features

- ✅ **Real-Time Monitoring** of node-level traffic and throughput
- 🚨 **Proactive Alert Triggers** based on event thresholds (latency, drops, congestion)
- 🔁 **Dynamic Response Logic** simulating auto-routing or traffic shaping
- 📊 **Simulation Visualization** using OMNeT++ GUI and log traces

---

## 🧠 Future Enhancements

- Add ML/AI support for adaptive alert scoring
- Real-world trace injection for benchmark testing
- Multi-protocol support (e.g., UDP, TCP, ICMP)
- Integrate SNMP-like interface for reporting

---

## 🤝 Contributions

Want to improve PANDA? Contributions are welcome! Fork the repo, make your changes, and submit a pull request.

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

Created with ❤️ by Sentinels
