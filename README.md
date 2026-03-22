# WORK IN PROGRESS
## PoE Powered ESP32-P4 Honeypot (Improved version of the $26 Honeypot)
The world's lowest cost honeypot appliance  
![ESP32-P4 Honeypot Image](https://github.com/Xorlent/PoE-Honeypot/blob/main/images/PoE-Honeypot.jpg)
## Background
After completing the [$26 Honeypot project](https://github.com/Xorlent/The-26-Dollar-Honeypot), I still hoped to build a version that could listen on an unlimited number of TCP ports, included support for UDP and ICMP, and required no additional programmer tool or disassembly.  Recently I found M5Stack's new [Unit-PoE-P4](https://shop.m5stack.com/products/unit-poe-with-esp32-p4) and got to work addressing the shortcomings of their earlier, less capable, and slightly more expensive PoESP32 device.
  
Use this honeypot in conjunction with the [ESP32-Watchman](https://github.com/Xorlent/ESP32-Watchman) for full physical and network sensing capabilities with a total cost of under $60.

## Requirements
1. M5Stack [Unit-PoE-P4](https://shop.m5stack.com/products/unit-poe-with-esp32-p4), currently $21.50 USD
2. USB-C cable for programming
3. A Syslog collector (free open source options exist, as well as Graylog Open)

## Functional Description
This project produces a honeypot that listens on any number of user-configurable TCP and UDP ports.  If activity is detected, a Syslog (UDP) message or an email is immediately sent with information about the source IP and port accessed.  The device can also be configured to alert on ICMP ping requests, but note the device will not respond to any pings if ICMP is enabled.  The device is reconfigurable via a USB-C serial console connection.  
## Programming
### Prepare configuration details for your device:  
- Host name
- Device IP address, gateway, and subnet mask
- DNS servers
- Syslog collector IP or SMTP relay IP
- Email to and from addresses if email (USE_SMTP) is configured
- NTP server
- TCP and/or UDP ports to listen on
### Configure and flash the device:
_Once you've successfully programmed a single unit, skip steps 1 & 2.  Repeating this process takes 3 minutes from start to finish._  
1. [Set up your Arduino programming environment](https://github.com/Xorlent/PoE-Honeypot/blob/main/ARDUINO-SETUP.md)
2. In Arduino, open the project file (PoE-Honeypot.ino)
   - Select Tools->Board->esp32 and select "ESP32P4 Dev Module"
   - Configure board settings according to the [Unit-PoE-P4 Board Configuration](https://github.com/Xorlent/PoE-Honeypot/blob/main/images/ESP32P4-Config.jpg)
3. Connect the Unit-PoE-P4 to your computer via USB
   - Select Tools->Port and select the device port
     - If you're unsure, unplug the device, look at the port list, then plug it back in and select the new entry
> [!WARNING]
> Do not plug the device into a PoE-powered Ethernet port until after step 6 or you risk damaging your USB port!
4. In Arduino
   - Edit Config.h with configuration details for the device
   - Select Sketch->Upload to flash the device
   - When you see something similar to the following, proceed to step 4
```
Writing at 0x000f4830 [==============================] 100.0% 495157/495157 bytes... 
Wrote 935984 bytes (495157 compressed) at 0x00010000 in 3.6 seconds (2098.6 kbit/s).
Hash of data verified.

Hard resetting via RTS pin...
```
5. In Arduino
   - Select Tools->Serial Monitor
   - Address any displayed configuration errors or warnings
6. When configuration is complete, disconnect the USB cable
7. Connect the device to a PoE network port and mount as appropriate
8. Configure your syslog alerts as appropriate
    - Add alert triggers based on events received from these devices to get immediate notice of possible malicious lateral movement
    - Example Syslog event for IP 10.70.103.12 connecting to TCP port 443:
    ```<36>Mar 22 21:12:52 PoE-Honeypot TCP/443 (https): Connection from 10.70.103.12```
    - Example Syslog event for IP 10.70.103.12 connecting to UDP port 137:  
    ```<36>Mar 22 21:04:56 PoE-Honeypot UDP/137 (netbios-ns): Connection from 10.70.103.12```
    - Example Syslog event for IP 10.70.103.12 sending a ping request to the honeypot:
    ```<36>Mar 22 21:15:45 PoE-Honeypot ICMP/Type 8 (echo-request): Ping request from 10.70.103.12```
## Guidance and Limitations
- The device produces Syslog UDP messages in the BSD / RFC 3164 format.
- Listening orts are fully user-configurable a few default personalities to choose from.
- It is recommended you exempt your honeypot IP addresses in any legitimate vulnerability or network scanners to avoid triggering alerts.
- The device will respond to pings (will not generate Syslog events) from any IP address within the routable network.

## Technical Information
- CPU and Memory
  - 360MHz dual core + 40MHz LP core RISC-V
  - 768KBytes RAM
  - 16MBytes Flash + 32MBytes PSRAM
- Operating Specifications
  - Operating temperature: 0°F (-17.7°C) to 104°F (40°C)
  - Operating humidity: 5% to 90% (RH), non-condensing
- Power Consumption
  - 6W maximum via 802.3af Power-over-Ethernet
- Ethernet
  - IP101GRI or TLK110 PHY
  - 10/100 Mbit twisted pair copper
  - IEEE 802.3af Power-over-Ethernet
