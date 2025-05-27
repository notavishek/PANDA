/*
 * NetPacket_m.h
 *
 *  Created on: May 28, 2025
 *      Author: Turja Dutta
 */
#ifndef __NETPACKET_M_H
#define __NETPACKET_M_H

#include <omnetpp.h>
using namespace omnetpp;

class NetPacket : public cPacket
{
  private:
    int srcId {-1};
    int destId{-1};

  public:
    NetPacket(const char *name=nullptr) : cPacket(name) {}

    void setSrc(int id)  { srcId  = id; }
    void setDest(int id) { destId = id; }
    int  getSrc()  const { return srcId;  }
    int  getDest() const { return destId; }

    NetPacket *dup() const override
    {
        auto *copy = new NetPacket(getName());
        copy->setByteLength(getByteLength());
        copy->setSrc(srcId);
        copy->setDest(destId);
        return copy;
    }
};
#endif
