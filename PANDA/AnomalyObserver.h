//
// PANDA: Proactive Alert Network for Detecting Anomalies
// Anomaly Observer Header File
//

#ifndef _PANDA_ANOMALYOBSERVER_H
#define _PANDA_ANOMALYOBSERVER_H

#include <omnetpp.h>
#include <vector>
#include <map>
#include <string>
#include <deque>

using namespace omnetpp;

struct PacketInfo {
    simtime_t timestamp;
    int size;
    std::string srcAddr;
    std::string destAddr;
    int protocol;
    std::string protocolName;
    std::string sourceModule;
};

class AnomalyObserver : public cSimpleModule, public cListener
{
private:
    // Parameters
    double packetThreshold;
    double timeWindow;
    double movingAverageWindow;
    double anomalyMultiplier;
    bool enableGUIAlerts;
    bool enableConsoleLogging;
    bool enableAlertForwarding;
    std::string monitoredZone;
    double ddosThreshold;
    double burstThreshold;
    double entropyThreshold;
    double checkInterval;
    double alertCooldown;

    // Statistics
    long packetCount;
    long totalBytes;
    long tcpCount;
    long udpCount;
    long otherCount;
    simtime_t lastAlertTime;

    // Data structures
    std::deque<PacketInfo> recentPackets;
    std::map<std::string, int> sourceIPCount;
    std::deque<std::pair<simtime_t, double>> movingAverageHistory;
    std::map<std::string, simtime_t> lastAlertTypes;

    // Timer
    cMessage *checkTimer;

    // Methods
    void analyzePacket(cPacket *packet, cComponent *source);
    void cleanOldPackets();
    void performAnomalyCheck();
    void updateMovingAverage(double currentValue);
    double getMovingAverage();
    void checkPacketThreshold(double packetsPerSecond);
    void checkDDoSPattern();
    void checkBurstTraffic(double packetsPerSecond);
    void checkProtocolAnomaly();
    bool canRaiseAlert(const std::string& alertType);
    void raiseAlert(const std::string& alertType, const std::string& message);

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;
    virtual void finish() override;
};

#endif
