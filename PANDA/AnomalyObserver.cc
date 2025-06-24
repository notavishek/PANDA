//
// PANDA: Proactive Alert Network for Detecting Anomalies
// Anomaly Observer Implementation
//

#include "AnomalyObserver.h"
#include <cmath>

Define_Module(AnomalyObserver);

void AnomalyObserver::initialize()
{
    // Get parameters
    packetThreshold = par("packetThreshold");
    timeWindow = par("timeWindow");
    movingAverageWindow = par("movingAverageWindow");
    anomalyMultiplier = par("anomalyMultiplier");
    enableGUIAlerts = par("enableGUIAlerts");
    enableConsoleLogging = par("enableConsoleLogging");
    enableAlertForwarding = par("enableAlertForwarding");
    monitoredZone = par("monitoredZone").stringValue();
    ddosThreshold = par("ddosThreshold");
    burstThreshold = par("burstThreshold");
    entropyThreshold = par("entropyThreshold");
    checkInterval = par("checkInterval");
    alertCooldown = par("alertCooldown");

    // Initialize statistics
    packetCount = 0;
    totalBytes = 0;
    tcpCount = 0;
    udpCount = 0;
    otherCount = 0;
    lastAlertTime = 0;

    // Schedule first check
    checkTimer = new cMessage("checkTimer");
    scheduleAt(simTime() + checkInterval, checkTimer);

    // Initialize moving average history
    movingAverageHistory.clear();

    // Subscribe to packet signals from all modules
    getSystemModule()->subscribe("packetSent", this);
    getSystemModule()->subscribe("packetReceived", this);
    getSystemModule()->subscribe("packetDropped", this);

    EV << "AnomalyObserver initialized for zone: " << monitoredZone << endl;
}

void AnomalyObserver::handleMessage(cMessage *msg)
{
    if (msg == checkTimer) {
        performAnomalyCheck();
        scheduleAt(simTime() + checkInterval, checkTimer);
    } else {
        delete msg;
    }
}

void AnomalyObserver::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    if (auto packet = dynamic_cast<cPacket*>(obj)) {
        analyzePacket(packet, source);
    }
}

void AnomalyObserver::analyzePacket(cPacket *packet, cComponent *source)
{
    // Update basic statistics
    packetCount++;
    totalBytes += packet->getByteLength();

    // Record timestamp for time-windowed analysis
    PacketInfo info;
    info.timestamp = simTime();
    info.size = packet->getByteLength();
    info.sourceModule = source->getFullPath();

    // Simple protocol detection based on packet name or size
    std::string packetName = packet->getName();
    if (packetName.find("tcp") != std::string::npos || packetName.find("TCP") != std::string::npos) {
        tcpCount++;
        info.protocol = 6; // TCP
        info.protocolName = "TCP";
    } else if (packetName.find("udp") != std::string::npos || packetName.find("UDP") != std::string::npos) {
        udpCount++;
        info.protocol = 17; // UDP
        info.protocolName = "UDP";
    } else {
        otherCount++;
        info.protocol = 0;
        info.protocolName = "OTHER";
    }

    // Generate pseudo IP addresses based on module names for demonstration
    info.srcAddr = source->getFullName();
    info.destAddr = "destination";

    // Store packet info with timestamp
    recentPackets.push_back(info);

    // Clean old packets outside time window
    cleanOldPackets();

    // Update source tracking for DDoS detection
    sourceIPCount[info.srcAddr]++;
}

void AnomalyObserver::cleanOldPackets()
{
    simtime_t cutoffTime = simTime() - timeWindow;

    auto it = recentPackets.begin();
    while (it != recentPackets.end()) {
        if (it->timestamp < cutoffTime) {
            // Remove from source count
            sourceIPCount[it->srcAddr]--;
            if (sourceIPCount[it->srcAddr] <= 0) {
                sourceIPCount.erase(it->srcAddr);
            }
            it = recentPackets.erase(it);
        } else {
            break; // packets are ordered by timestamp
        }
    }
}

void AnomalyObserver::performAnomalyCheck()
{
    if (recentPackets.empty()) return;

    // Calculate current metrics
    double packetsPerSecond = recentPackets.size() / timeWindow;
    double bytesPerSecond = 0;

    for (const auto& packet : recentPackets) {
        bytesPerSecond += packet.size;
    }
    bytesPerSecond /= timeWindow;

    // Update moving average
    updateMovingAverage(packetsPerSecond);

    // Perform various anomaly checks
    checkPacketThreshold(packetsPerSecond);
    checkDDoSPattern();
    checkBurstTraffic(packetsPerSecond);
    checkProtocolAnomaly();

    // Log current statistics
    if (enableConsoleLogging) {
        EV << "Zone: " << monitoredZone
           << " | PPS: " << packetsPerSecond
           << " | BPS: " << bytesPerSecond
           << " | TCP: " << tcpCount
           << " | UDP: " << udpCount
           << " | Unique Sources: " << sourceIPCount.size() << endl;
    }
}

void AnomalyObserver::updateMovingAverage(double currentValue)
{
    movingAverageHistory.push_back({simTime(), currentValue});

    // Remove old values outside moving average window
    simtime_t cutoffTime = simTime() - movingAverageWindow;
    auto it = movingAverageHistory.begin();
    while (it != movingAverageHistory.end()) {
        if (it->first < cutoffTime) {
            it = movingAverageHistory.erase(it);
        } else {
            break;
        }
    }
}

double AnomalyObserver::getMovingAverage()
{
    if (movingAverageHistory.empty()) return 0;

    double sum = 0;
    for (const auto& entry : movingAverageHistory) {
        sum += entry.second;
    }
    return sum / movingAverageHistory.size();
}

void AnomalyObserver::checkPacketThreshold(double packetsPerSecond)
{
    if (packetsPerSecond > packetThreshold) {
        if (canRaiseAlert("THRESHOLD")) {
            raiseAlert("PACKET_THRESHOLD_EXCEEDED",
                      "Packet rate (" + std::to_string(packetsPerSecond) +
                      " pps) exceeds threshold (" + std::to_string(packetThreshold) + " pps)");
        }
    }
}

void AnomalyObserver::checkDDoSPattern()
{
    // Check for potential DDoS: many unique source modules with high packet rate
    if (sourceIPCount.size() > 3) { // More than 3 unique sources
        int highVolumeModules = 0;
        for (const auto& entry : sourceIPCount) {
            if (entry.second > ddosThreshold / sourceIPCount.size()) {
                highVolumeModules++;
            }
        }

        if (highVolumeModules > 2 && canRaiseAlert("DDOS")) {
            raiseAlert("POTENTIAL_DDOS",
                      "Potential DDoS detected: " + std::to_string(sourceIPCount.size()) +
                      " unique sources, " + std::to_string(highVolumeModules) + " high-volume sources");
        }
    }
}

void AnomalyObserver::checkBurstTraffic(double packetsPerSecond)
{
    double movingAvg = getMovingAverage();
    if (movingAvg > 0 && packetsPerSecond > movingAvg * anomalyMultiplier) {
        if (canRaiseAlert("BURST")) {
            raiseAlert("TRAFFIC_BURST",
                      "Traffic burst detected: current " + std::to_string(packetsPerSecond) +
                      " pps vs average " + std::to_string(movingAvg) + " pps");
        }
    }
}

void AnomalyObserver::checkProtocolAnomaly()
{
    if (recentPackets.size() < 10) return; // Need sufficient data

    // Calculate protocol distribution entropy
    double totalPackets = recentPackets.size();
    double tcpRatio = tcpCount / totalPackets;
    double udpRatio = udpCount / totalPackets;
    double otherRatio = otherCount / totalPackets;

    double entropy = 0;
    if (tcpRatio > 0) entropy -= tcpRatio * log2(tcpRatio);
    if (udpRatio > 0) entropy -= udpRatio * log2(udpRatio);
    if (otherRatio > 0) entropy -= otherRatio * log2(otherRatio);

    // Low entropy might indicate protocol-specific attacks
    if (entropy < entropyThreshold && canRaiseAlert("PROTOCOL")) {
        raiseAlert("PROTOCOL_ANOMALY",
                  "Low protocol entropy detected: " + std::to_string(entropy) +
                  " (TCP:" + std::to_string(tcpRatio) + ", UDP:" + std::to_string(udpRatio) + ")");
    }
}

bool AnomalyObserver::canRaiseAlert(const std::string& alertType)
{
    simtime_t currentTime = simTime();
    auto it = lastAlertTypes.find(alertType);

    if (it == lastAlertTypes.end() || (currentTime - it->second) > alertCooldown) {
        lastAlertTypes[alertType] = currentTime;
        return true;
    }
    return false;
}

void AnomalyObserver::raiseAlert(const std::string& alertType, const std::string& message)
{
    std::string fullMessage = "[" + monitoredZone + "] " + alertType + ": " + message;

    // GUI Alert (bubble)
    if (enableGUIAlerts) {
        bubble(fullMessage.c_str());
        getDisplayString().setTagArg("i", 1, "red"); // Change color to red

        // Schedule to reset color after 5 seconds
        cMessage *resetColor = new cMessage("resetColor");
        resetColor->addPar("resetColor") = true;
        scheduleAt(simTime() + 5.0, resetColor);
    }

    // Console logging
    if (enableConsoleLogging) {
        EV << "*** ALERT *** " << fullMessage << " at time " << simTime() << endl;
    }

    // Alert forwarding (if enabled and gate connected)
    if (enableAlertForwarding && hasGate("alertOut") && gate("alertOut")->isConnected()) {
        cMessage *alertMsg = new cMessage("AlertMessage");
        alertMsg->addPar("alertType") = alertType.c_str();
        alertMsg->addPar("message") = fullMessage.c_str();
        alertMsg->addPar("timestamp") = simTime().dbl();
        alertMsg->addPar("zone") = monitoredZone.c_str();
        send(alertMsg, "alertOut");
    }

    // Update statistics
    emit(registerSignal("alertRaised"), 1);
}

void AnomalyObserver::finish()
{
    // Record final statistics
    recordScalar("totalPacketsAnalyzed", packetCount);
    recordScalar("totalBytesAnalyzed", totalBytes);
    recordScalar("uniqueSourceModules", (long)sourceIPCount.size());
    recordScalar("tcpPacketCount", tcpCount);
    recordScalar("udpPacketCount", udpCount);
    recordScalar("otherPacketCount", otherCount);

    if (enableConsoleLogging) {
        EV << "AnomalyObserver [" << monitoredZone << "] finished. "
           << "Analyzed " << packetCount << " packets, "
           << totalBytes << " bytes from " << sourceIPCount.size() << " unique sources" << endl;
    }
}
