# NetDelayAnalyser | Team Vicodin

## Introduction

NetDelayAnalyser is a web-based packet capture analysis tool.

## Installation and Setup
- pip packages :
    bokeh,
    numpy,
    pyshark,
    sys,
    math,
    collections,
    scapy (rdpcap, TCP, IP),
    pandas
    
- npm packages :
    npm≥20,
    vite,
    nodejs≥20,
    bootstrap,
    react-router-dom
- To initialize the node js + mongodb servers: open two separate cmd line panes; paste npm run dev in the first and npm run build in the second. Finally, run node server.js in the second pane. Now visit [localhost:5137](http://localhost:5173/) to visit the site.
  
## Feature Details

The analysis we were able to implement for delay categorisation and congestion / bottleneck identification was threefold:

### Round Trip Time Analysis

- This line of analysis deals exclusively with TCP packets, as MQTT primarily uses TCP for communication. Furthermore, most of the packets in the example files present in the problem statement were also communicated through TCP, further reinforcing the design decision of focussing heavily on TCP.
- We further divide our Round Trip Analysis into three separate filtered categories:
    - Filtered by conversation: For each conversation, i.e. communication between an IP pair, we plot:
        - RTT, which is present in the packet containing the acknowledgement message sent by the receiver.
        - Delay, which is computed as the logged time difference between two successive packets in the capture.
        - Correlation between outliers and packet length (NOTE: we noticed that a significant proportion of outliers all belonged to the same ‘category’ of packet, viz. packets containing acknowledgement messages. Upon digging deeper, we found that this is not a ‘delay’ but rather a TCP optimisation. The protocol itself might delay the sending of the acknowledgement message. Suppose a message was sent from node A to node B. The protocol might wait for a packet to be queued to be send from B back to A, and then piggyback the acknowledgement message onto this packet, thereby preventing an additional packet containing very little information to be sent).
    - Filtered by source: This is an analysis view for plotting round trip time and outlier correlation based on source IP. The motivation behind this is to identify which individual IPs are causing the greatest round trip time delays.
    - No filter / global: This is a cumulative analysis view across all conversations of the packet capture. We plot the following:
        - The percentage of outliers (mean + 2 * stdev) for round trip time grouped by source IP.
        - The percentage of outliers for delay, grouped by source IP.
        - Correlation of packet length and RTT across all packets.

### Protocol Distribution Analysis

- This line of analysis is meant to help identify congestion in the network.
- First, we plot the total delta time (time between successive packets being captured in the packet capture) for each individual transfer protocol encountered. The purpose of this is to indicate to the application programmer where the network is spending a majority of its time.
- We next identify the IP pairs which communicate the most for a given protocol, based on the number of packets transmitted between two given IP addresses. The purpose behind this is to identify bottlenecks in the network; if a single pair of addresses is overly burdened, the network designer could consider increasing bandwidth between those two IPs, thereby leading to performance gains.

### Packet Loss Analysis

- The pie chart represents the proportion of packets lost after grouping them on the basis of
    - Retransmissions - Repeated acknowledgment packets sent by the receiver for the same sequence number, signaling a missing packet and prompting retransmission.
    - Lost segments - Occur due to network congestion, transmission errors, or unstable links, resulting in dropped packets.
    - Spurious Retransmissions -  Triggered by delayed acknowledgments or path asymmetry, leading to unnecessary retransmissions.
    - Duplicate ACKs - Result from a missing packet in the sequence, causing the receiver to repeatedly acknowledge the last successfully received packet.
- It then displays this data in tabular format to display the number of packets lost
- It gives a percentage of how many packets out of the total were lost
- It creates a stacked bar graph of IPs that contribute more than 5% of the total packets lost to pinpoint the possible sources of the most packet loss. This stacked bar graph is also subdivided like the pie chart

### Retransmission Delay Analysis

- This analysis uses thresholding to find out the possible sources of transmission delays and specifically retransmission delays. It only displays IPs that contribute more than 5% of the total retransmission delay time
- It creates a stacked bar graph representing the total retransmission delay of an ip after grouping the delays on the basis of
    - **Spurious Retransmissions**: Caused by delayed acknowledgments or path asymmetry, leading to unnecessary retransmissions.
    - **Fast Retransmissions**: Triggered by three duplicate ACKs, indicating packet loss and prompting immediate retransmission.
    - **Timeout Retransmissions**: Occur when the sender does not receive an acknowledgment within the retransmission timeout (RTO) period.

### Individual Graph Plotting

- While our tool is accompanied by a website, where all our plots and aggregated and displayed, the scripts present in the `plotting_scripts` directory can also be used independently.
- They can be called as follows: `python3 <plotting-script>.py <capture-file>.pcapng` (assuming the capture file is present in the same directory as the plotting script.
- Each script generates interactive plots using the `bokeh` library. In some cases, the plots are standalone, whereas in other cases, they have been grouped together (depending on how we planned to use them within the website). Regardless, they will still be accessible in any browser.

## Future Work

While we *were* able to implement a fair share of what we initially planned to, we were certainly not able to implement everything. The following are tasks we plan to work on in the future:

- Adding functionality to categorise more kinds of delays, as well as other metrics which would focus on other protocols.
- Integrating exporting functionality within the website (although the end user can still obtain these plots by running the plotting scripts manually).
- Adding summary statistics to the dashboard page (the ones currently present are placeholder values).
- And many more…
