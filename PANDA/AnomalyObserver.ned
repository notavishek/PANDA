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
// Anomaly Observer Module Definition
//

package panda;

simple AnomalyObserver
{
    parameters:
        // Detection parameters
        double packetThreshold = default(100);  // packets per second threshold
        double timeWindow = default(5.0);       // time window for analysis (seconds)
        double movingAverageWindow = default(10.0); // moving average window (seconds)
        double anomalyMultiplier = default(3.0); // multiplier for moving average threshold
        
        // Alert parameters
        bool enableGUIAlerts = default(true);
        bool enableConsoleLogging = default(true);
        bool enableAlertForwarding = default(false);
        string monitoredZone = default("Unknown");
        
        // Detection sensitivity
        double ddosThreshold = default(500);     // DDoS detection threshold
        double burstThreshold = default(200);    // Burst traffic threshold
        double entropyThreshold = default(2.0);  // Entropy threshold for protocol analysis
        
        // Timing parameters
        double checkInterval = default(1.0);     // how often to check for anomalies (seconds)
        double alertCooldown = default(30.0);    // cooldown period between same-type alerts
        
        @display("i=block/control");
        @class(AnomalyObserver);
        
    gates:
        // Optional gates for alert forwarding
        output alertOut @loose;
        input alertIn @loose;
}