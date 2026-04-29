# Grafana Dashboard Integration

The Graphic Engine is currently in its final stages of development. At this point, we have successfully built and integrated a functional Grafana dashboard with parsed network data.

This dashboard visualizes DNP3 traffic and provides several important monitoring and analysis features:

## Features

* **Raw Packet Table**
  Displays parsed packet data including timestamps, source/destination IPs, ports, and protocol information.

* **Top Source and Destination IPs**
  Shows the most active devices on the network for quick identification of major communicators.

* **Top Destination Ports**
  Highlights frequently used destination ports to help identify service usage and potential anomalies.

* **Packets Over Time**
  Visualizes traffic patterns over time, making it easier to detect spikes or unusual behavior.

* **Average Packet Size**
  Tracks average packet sizes to help identify abnormal payload activity.

* **Protocol Distribution**
  Displays protocol usage across the environment, currently focused on DNP3 traffic.

## Current Status

* Functional Grafana dashboard completed
* Successfully integrated with parsed network data
* Supports real-time traffic visualization and analysis
* Ready for final testing and optimization

## Purpose

This dashboard provides analysts with an easy-to-use interface for monitoring industrial network traffic, improving visibility, and supporting anomaly detection within DNP3 environments.

