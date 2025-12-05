# AI Anomaly Detection Network Monitoring

<img src="Images/P0001.jpg" width="75%" />

## Objective

This project implements an AI-powered network anomaly detection system designed to monitor and analyze network traffic in real time. Using machine learning techniques, the programs automatically identify unusual patterns and deviations from normal network behavior that may indicate security threats, performance issues, or unauthorized access. The system collects and preprocesses network data, extracts relevant features, trains anomaly detection models, and provides real-time alerts and visualizations to help network administrators quickly detect and respond to potential anomalies. Its adaptive approach reduces false positives by learning normal traffic patterns and continuously improving through feedback and retraining.

## Detailed Python Program Descriptions

AI_AnomalyDetectionNetworkMonitoring repository based on the filenames and typical roles in network anomaly detection projects:

- AnalysisReportNetwork.py : Generates detailed analysis reports summarizing detected network anomalies, model performance metrics, and overall monitoring results.

- Network_AI_Monitoring.py : Implements the core AI-based network monitoring system using machine learning models to detect anomalies in network traffic.

- Network_AI_Monitoring_Deep_Learning_LSTM.py: Extends the AI monitoring system by integrating a deep learning model based on LSTM (Long Short-Term Memory) networks for improved detection of temporal anomalies in sequential network data.

- Network_AI_Monitoring_Level3.py:  Provides an advanced level (Level 3) AI monitoring module, likely incorporating more sophisticated features or detection algorithms for enhanced anomaly identification.

- Network_AI_Monitoring_Level4.py: Represents the highest level (Level 4) of AI monitoring with further improvements in detection accuracy, possibly combining multiple models or advanced ensemble techniques.

- Network_Without_AI_Monitoring.py: Implements a baseline network monitoring system without AI, using traditional rule-based or statistical methods for anomaly detection.

- Network_Without_AI_Monitoring_Level2.py: An enhanced version of the non-AI monitoring system with additional features or refined heuristics for anomaly detection.

- Network_Without_AI_Monitoring_Level3.py: Further development of the non-AI monitoring system, adding more complex rules or statistical checks to improve detection capability.

- Network_Without_AI_Monitoring_Level4.py:  The most advanced iteration of the non-AI monitoring system, possibly integrating multiple detection strategies without machine learning.

- ScanBluetoothInformation.py: Scans and collects Bluetooth device information in the network environment, potentially to detect anomalies or unauthorized devices via Bluetooth traffic analysis.

- ScanBluetoothInformation3D.py: Scans Bluetooth devices, collects signal data from multiple positions, and uses trilateration to estimate and visualize their 3D locations.

- RealTimeIPVisualizer.py : This program visualizes IP addresses in real-time as colored 3D cubes based on their frequency, combining the last two octets in the Z-coordinate, with interactive tooltips showing full IP details. This allows you to see what's going on on your PC.

- BluetoothEarphone3DHeadPositionEstimator.py : This program detects, tracks, and estimates the 3D positions of nearby Bluetooth devices, such as wireless earphones.   It uses Kalman-filtered RSSI measurements combined with trilateration to improve accuracy.   It also supports trusted device lists, intrusion alerts, and optional 3D visualization.

- Network_AI_Monitoring_Level6.py:  Network/Bluetooth monitoring, advanced detection with AI + adaptive standby.
  Preparation and development of a barrier against artificial intelligence viruses.
  Remark it is only a draft for instance... I invite you to follow its development.
  
- WirelessLANAnalyzer.py: This application scans available WiFi networks and detects devices connected to your local network. It works on Windows and Linux, provides signal strength, and identifies device manufacturers, making network management simple and efficient.

- WirelessDeviceInspector.py: This is a tool that automatically scans your local WiFi or Ethernet network, detects all connected phones and laptops, and displays or exports the results.
It dynamically adapts to your network range, making it easy to monitor device presence across different environments.


Nota : The ultimate goal will be to bring together all my detection developments, including sound-based detection, and add artificial intelligence to perform data fusion for detections that may later be used for robots. 

I also plan to add a 3D spatial representation of the data in future developments. I'm currently thinking about the best method to achieve this. Later, this will serve as a way to visualize how the robot perceives its environment.

There is still a lot of work to be done, but I’m confident I’ll get there. I invite you to follow my progress as I continue developing.



