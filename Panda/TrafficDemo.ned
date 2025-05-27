channel Link extends ned.DatarateChannel
{
    delay    = 1us;
    datarate = 100Mbps;
}

simple TrafficNode
{
    parameters:
        int    nodeId;
        double sendInterval @unit(s) = default(0.01s);
        int    packetSize   @unit(B) = default(1000B);
    gates:
        input  in;
        output out;
}

simple TrafficMonitor
{
    gates:
        input  in[6];
        output out[6];
}

network TrafficRingDemo
{
    parameters:
        int numNodes = default(6);
    submodules:
        Rahat: TrafficNode {
            parameters:
                nodeId = 0;
            @display("p=100,100;i=device/laptop");
        }
        Avishek: TrafficNode {
            parameters:
                nodeId = 1;
            @display("p=250,50;i=device/laptop");
        }
        Turja: TrafficNode {
            parameters:
                nodeId = 2;
            @display("p=400,100;i=device/laptop");
        }
        Rizve: TrafficNode {
            parameters:
                nodeId = 3;
            @display("p=400,250;i=device/laptop");
        }
        Eju: TrafficNode {
            parameters:
                nodeId = 4;
            @display("p=250,300;i=device/laptop");
        }
        Moin: TrafficNode {
            parameters:
                nodeId = 5;
            @display("p=100,250;i=device/laptop");
        }
        Monitor: TrafficMonitor {
            @display("p=250,175;i=device/router");
        }
    connections allowunconnected:
        Rahat.out --> Link --> Monitor.in[0];
        Monitor.out[0] --> Link --> Avishek.in;

        Avishek.out --> Link --> Monitor.in[1];
        Monitor.out[1] --> Link --> Turja.in;

        Turja.out --> Link --> Monitor.in[2];
        Monitor.out[2] --> Link --> Rizve.in;

        Rizve.out --> Link --> Monitor.in[3];
        Monitor.out[3] --> Link --> Eju.in;

        Eju.out --> Link --> Monitor.in[4];
        Monitor.out[4] --> Link --> Moin.in;

        Moin.out --> Link --> Monitor.in[5];
        Monitor.out[5] --> Link --> Rahat.in;
}
