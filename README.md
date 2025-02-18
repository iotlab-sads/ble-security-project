# BLE Security Project

## Overview

This project is inspired by the BlueShield research and aims to detect spoofed BLE (Bluetooth Low Energy) beacons. It replicates the methodology of BlueShield by monitoring BLE traffic, analyzing advertising intervals, and identifying anomalies that suggest spoofing activities. The project comprises several components that work together to advertise beacons, capture and analyze BLE packets, and monitor for spoofing events.

## Project Structure

- **beacon.py**:
  - Runs on a Raspberry Pi.
  - Sets up a BLE beacon using the iBeacon advertisement format.
  - Includes functionality to change the Bluetooth MAC address using a custom vendor command.
- **packet.py**:

  - Runs on a computer connected to an nRF52840 dongle.
  - Captures BLE packets in JSON format via tshark.
  - Processes BLE packets to calculate statistics such as RSSI averages and advertising intervals.
  - Saves the processed data to a MongoDB database.

- **detect.py**:
  - Monitors BLE traffic in real time.
  - Compares the advertising intervals from captured packets with pre-established minimum thresholds stored in the MongoDB database.
  - Detects spoofing events when the measured intervals fall below the allowed minimum and sends automated alert emails.

## Requirements

- **Python 3.x**
- **BLE Tools and Libraries**:
  - dbus, GLib, and PyGObject (for Bluetooth operations)
  - tshark (for packet capture)
  - hcitool (for Bluetooth configuration)
- **Python Packages**:
  - pymongo (for MongoDB integration)
  - tabulate, wcwidth (for formatted output)
  - smtplib and email libraries (for sending alert emails)
- **MongoDB**: Ensure MongoDB is installed and running on your machine.
- **Email SMTP Access**: Update the email configuration in `detect.py` with valid credentials.

## Setup Instructions

1. **MongoDB**:

   - Install MongoDB and ensure it is running (default URI: `mongodb://localhost:27017/`).
   - Adjust `MONGO_URI` in `detect.py` if your database is located elsewhere.

2. **Email Configuration**:

   - In `detect.py`, update `EMAIL_CONFIG` with your SMTP server, port, sender's email, password (or app-specific password), and receiver's email.

3. **Install Dependencies**:

   - Use pip to install the required Python packages:

     ```bash
     pip install dbus-python pymongo tabulate wcwidth
     ```

4. **BLE Tools Setup**:
   - Ensure that BLE tools such as `tshark` and `hcitool` are installed and properly configured on your system.
   - Verify that your Bluetooth adapter supports BLE.

## Usage

### beacon.py

- **Purpose**: Sets up a BLE beacon and optionally changes the Bluetooth MAC address.
- **Usage**:  
  Run on a Raspberry Pi.

  ```bash
  python beacon.py
  ```

- **Customization**:
  - Modify beacon parameters (UUID, major, minor, tx_power) directly in the script.
  - Change the target MAC address as required.

### packet.py

- **Purpose**: Captures BLE packets, processes them to compute per-channel statistics, and stores the results in MongoDB.
- **Usage**:  
  Run on a computer with an nRF52840 dongle.

  ```bash
  python packet.py <interface_or_auto> <advertising_address/all> <UUID/all> [packet_count]
  ```

- **Example**:

  ```bash
  python packet.py auto all 12345678-1234-1234-1234-1234567890ab 20
  ```

- **Parameters**:
  - `<interface_or_auto>`: Specify the Bluetooth interface name or use "auto" to detect automatically.
  - `<advertising_address/all>`: Provide a specific BLE advertising address to filter or "all" to capture every address.
  - `<UUID/all>`: Filter by a specific UUID or use "all" for no UUID filtering.
  - `[packet_count]`: (Optional) Number of packets to capture per channel (default is 20).

### detect.py

- **Purpose**: Monitors BLE traffic for spoofing events, compares real-time advertising intervals with historical minimum delays, and sends alert emails upon detection.
- **Usage**:

  ```bash
  python detect.py <target_address/all> <target_uuid/all>
  ```

- **Example**:

  ```bash
  python detect.py all 12345678-1234-1234-1234-1234567890ab
  ```

- **Parameters**:
  - `<target_address/all>`: The BLE advertising address to monitor or "all" for any address.
  - `<target_uuid/all>`: The specific UUID to monitor for or "all" to disable UUID filtering.

## Acknowledgements

This project draws inspiration from the BlueShield research to combat spoofing beacons in BLE environments. It aims to provide a practical implementation of spoofing detection mechanisms and enhance the security of BLE communications.
