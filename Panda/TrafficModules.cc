#include <omnetpp.h>
#include "NetPacket_m.h"
using namespace omnetpp;

/* ----------------  handy lookup ---------------- */
static const char *NodeNames[] =
    { "Rahat", "Avishek", "Turja", "Rizve", "Eju", "Moin" };

/* =================  TrafficNode  ================ */
class TrafficNode : public cSimpleModule
{
    simtime_t sendInterval;
    int       pktBytes;
    int       myId;
    int       numNodes;
    cMessage *sendEvt = nullptr;

  protected:
    void initialize() override
    {
        sendInterval = par("sendInterval");
        pktBytes     = par("packetSize");
        myId         = par("nodeId");
        numNodes     = getParentModule()->par("numNodes").intValue();

        sendEvt = new cMessage("sendEvt");
        scheduleAt(simTime() + sendInterval, sendEvt);
    }

    void handleMessage(cMessage *msg) override
    {
        /* ----- generate new packet ----- */
        if (msg == sendEvt) {
            int dest;
            do { dest = intuniform(0, numNodes-1); } while (dest == myId);

            auto *pkt = new NetPacket();
            pkt->setByteLength(pktBytes);
            pkt->setSrc(myId);
            pkt->setDest(dest);

            char label[64];
            sprintf(label, "%s → %s", NodeNames[myId], NodeNames[dest]);
            pkt->setName(label);

            EV << "Generated " << pkt->getName() << '\n';
            send(pkt, "out");
            scheduleAt(simTime() + sendInterval, sendEvt);
            return;
        }

        /* ----- receive / forward ----- */
        auto *pkt = check_and_cast<NetPacket *>(msg);
        if (pkt->getDest() == myId) {
            EV << "Delivered " << pkt->getName() << " to " << NodeNames[myId] << '\n';
            delete pkt;                      // consume
        } else {
            EV << "Forwarding " << pkt->getName() << " at " << NodeNames[myId] << '\n';
            send(pkt, "out");                // clockwise
        }
    }

    void finish() override { cancelAndDelete(sendEvt); }
};

Define_Module(TrafficNode);

/* =================  TrafficMonitor  ============= */
class TrafficMonitor : public cSimpleModule
{
    long totalPkts{}, totalBytes{};
    long intPkts{}, intBytes{};
    cMessage *tick = nullptr;

  protected:
    void initialize() override
    {
        tick = new cMessage("tick");
        scheduleAt(simTime()+SimTime(1), tick);
    }

    void handleMessage(cMessage *msg) override
    {
        if (msg == tick) {                       // periodic stats
            recordScalar("pktsLastSec", intPkts);
            recordScalar("bytesLastSec", intBytes);
            intPkts = intBytes = 0;
            scheduleAt(simTime()+SimTime(1), tick);
            return;
        }

        auto *pkt = check_and_cast<NetPacket *>(msg);
        totalPkts++;        intPkts++;
        totalBytes += pkt->getByteLength();
        intBytes   += pkt->getByteLength();

        int gateIx = msg->getArrivalGate()->getIndex();
        EV << "Monitor saw " << pkt->getName() << '\n';
        send(pkt, "out", gateIx);               // straight through
    }

    void finish() override
    {
        recordScalar("totalPackets", totalPkts);
        recordScalar("totalBytes",   totalBytes);
        cancelAndDelete(tick);
    }
};

Define_Module(TrafficMonitor);
