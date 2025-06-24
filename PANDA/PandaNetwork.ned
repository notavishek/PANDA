//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
//
// PANDA: Proactive Alert Network for Detecting Anomalies
// Network Topology Definition
//

package panda;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.inet.WirelessHost;
import inet.node.wireless.AccessPoint;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network PandaNetwork
{
    parameters:
        @display("bgb=1200,800;bgi=background/terrain,s");
        
    submodules:
        // Network configurator
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }
        
        // Wireless medium for IoT subnet
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=200,50");
        }
        
        // Central infrastructure
        centralRouter: Router {
            @display("p=600,400;i=device/router");
        }
        
        mainSwitch: EthernetSwitch {
            @display("p=600,300;i=device/switch");
        }
        
        // LAN A components
        lanA_switch: EthernetSwitch {
            @display("p=300,200;i=device/switch");
        }
        
        lanA_host1: StandardHost {
            @display("p=200,150;i=device/pc");
        }
        
        lanA_host2: StandardHost {
            @display("p=400,150;i=device/pc");
        }
        
        lanA_server: StandardHost {
            @display("p=300,100;i=device/server");
        }
        
        // LAN B components
        lanB_switch: EthernetSwitch {
            @display("p=900,200;i=device/switch");
        }
        
        lanB_host1: StandardHost {
            @display("p=800,150;i=device/pc");
        }
        
        lanB_host2: StandardHost {
            @display("p=1000,150;i=device/pc");
        }
        
        lanB_server: StandardHost {
            @display("p=900,100;i=device/server");
        }
        
        // IoT subnet components
        iot_accessPoint: AccessPoint {
            @display("p=600,600;i=device/accesspoint");
        }
        
        iot_device1: WirelessHost {
            @display("p=500,650;i=device/sensor");
        }
        
        iot_device2: WirelessHost {
            @display("p=700,650;i=device/sensor");
        }
        
        iot_device3: WirelessHost {
            @display("p=550,700;i=device/sensor");
        }
        
        iot_device4: WirelessHost {
            @display("p=650,700;i=device/sensor");
        }
        
        // Central monitoring server
        monitoringServer: StandardHost {
            @display("p=600,500;i=device/server2");
        }
        
        // Anomaly detection modules
        anomalyObserver_LanA: AnomalyObserver {
            @display("p=150,200;i=block/control");
        }
        
        anomalyObserver_LanB: AnomalyObserver {
            @display("p=1050,200;i=block/control");
        }
        
        anomalyObserver_IoT: AnomalyObserver {
            @display("p=750,600;i=block/control");
        }
        
        anomalyObserver_Central: AnomalyObserver {
            @display("p=700,400;i=block/control");
        }
        
    connections:
        // Main backbone connections
        mainSwitch.ethg++ <--> centralRouter.ethg++;
        
        // LAN A connections
        lanA_switch.ethg++ <--> mainSwitch.ethg++;
        lanA_host1.ethg++ <--> lanA_switch.ethg++;
        lanA_host2.ethg++ <--> lanA_switch.ethg++;
        lanA_server.ethg++ <--> lanA_switch.ethg++;
        
        // LAN B connections
        lanB_switch.ethg++ <--> mainSwitch.ethg++;
        lanB_host1.ethg++ <--> lanB_switch.ethg++;
        lanB_host2.ethg++ <--> lanB_switch.ethg++;
        lanB_server.ethg++ <--> lanB_switch.ethg++;
        
        // IoT subnet connections
        iot_accessPoint.ethg++ <--> mainSwitch.ethg++;
        
        // Monitoring server connection
        monitoringServer.ethg++ <--> mainSwitch.ethg++;
}