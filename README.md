# The $26 Honeypot
The world's lowest cost honeypot appliance  
![PoESP32 Honeypot Image](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/images/PoESP32-Honeypot.jpg)
## Background
After completing the [$32 network environmental monitoring project](https://github.com/Xorlent/PoESP32-SNMP-Environmental-Monitor) and marveling at the miniscule cost and excellent packaging of the M5Stack PoESP32 device, I contemplated other applications where this device could provide value.  A network honeypot was the first thing that came to mind.  For maximum performance and minimal code footprint, this code uses TCP sockets directly instead of Arduino wrappers.  
  
Use this honeypot in conjunction with an [ESP32-Watchman](https://github.com/Xorlent/ESP32-Watchman), for full physical and cyber sensing capabilities with a total cost of under $70.

## Requirements
1. M5Stack [PoESP32 device](https://shop.m5stack.com/products/esp32-ethernet-unit-with-poe), currently $25.90 USD
2. A single [M5Stack ESP32 Downloader kit](https://shop.m5stack.com/products/esp32-downloader-kit), currently $9.95 USD
3. A Syslog collector (free open source options exist, as well as Graylog Open)

## Functional Description
This project produces a honeypot that listens on commonly targeted TCP ports.  If activity is detected, a Syslog (UDP) message is immediately sent with information about the source IP and port accessed.  The device is not remotely managable.  If you need to change any configuration details, a re-flash/re-programming is necessary:
- Host name
- Device IP address information
- DNS servers
- Syslog collector IP
- NTP server  
> [!NOTE]
> All configuration fields are necessary for the honeypot to function properly.
## Programming
_Once you've successfully programmed a single unit, skip step 1.  Repeating this process takes 5 minutes from start to finish._
1. [Set up your Arduino programming environment](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/ARDUINO-SETUP.md)
2. Disassemble the PoESP32 case
   - You will need a 1.5 mm (M2) allen wrench to remove a single screw [pic](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/images/1-Allen.jpg)
   - Inserting a small flat head screwdriver into the slots flanking the Ethernet jack [pic](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/images/2-Slots.jpg), carefully separate the case halves; work it side by side to avoid damage [pic](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/images/3-Tabs.jpg)
> [!TIP]
> If you have fingernails, it can be quicker to slide a nail between the case halves, starting with the end opposite the Ethernet port and using another nail to pull the retaining tabs back
3. In Arduino, open the project file (PoESP32-Honeypot.ino)
   - Edit the hostname, IP address, subnet, gateway, DNS, Syslog collector IP, and NTP server info at the very top of the file.
   - Select Tools->Board->esp32 and select "ESP32 Dev Module"
4. With the USB-to-serial adapter unplugged, insert the pins in the correct orientation on the back of the PoESP32 mainboard [pic](https://github.com/Xorlent/The-26-Dollar-Honeypot/blob/main/images/4-Programmer.jpg)
> [!WARNING]
> Do not plug the PoESP32 device into Ethernet until after step 7 or you risk damaging your USB port!
5. With light tension applied to ensure good connectivity to the programming through-hole vias on the PoESP32 (see step 4 pic), plug in the USB-to-serial adapter
   - The device is now in bootloader mode
6. In Arduino
   - Select Tools->Port and select the USB-to-serial adapter
     - If you're unsure, unplug the USB-to-serial adapter, look at the port list, then plug it back in and select the new entry (repeating step 5)
   - Select Sketch->Upload to flash the device
   - When you see something similar to the following, proceed to step 7
     ```
     Writing at 0x000d0502... (100 %)
     Wrote 790896 bytes (509986 compressed) at 0x00010000 in 8.9 seconds (effective 714.8 kbit/s)...
     Hash of data verified.

     Leaving...
     Hard resetting via RTS pin...
7. Disconnect the USB-to-serial adapter and reassemble the case
8. Connect the PoESP32 to a PoE network port and mount as appropriate
   - The holes in the PoESP32 case work great with zip ties for rack install or screws if attaching to a backboard
9. Configure your syslog alerts as appropriate
    - Add alert triggers based on events received from these devices to get immediate notice of possible malicious lateral movement
    - Example Syslog event from IP 10.70.103.12 connecting to TCP port 80:  
    ```<116>Jun 05 17:48:40 PoESP-Honeypot TCP/80: Connection from 10.70.103.12```

## Guidance and Limitations
- The device produces Syslog UDP messages in the BSD / RFC 3164 format.
- Listening TCP ports are user-configurable within the source file, with a few default personalities to choose from.
- There is no throttling mechanism in place.
  - The honeypot will attempt to send one message for every single connection attempt.
- It is recommended you exempt your honeypot IP addresses in any legitimate vulnerability or network scanners to avoid spam.
- The device will respond to pings (will not generate Syslog events) from any IP address within the routable network.

## Technical Information
- Operating Specifications
  - Operating temperature: 0°F (-17.7°C) to 140°F (60°C)
  - Operating humidity: 5% to 90% (RH), non-condensing
- Power Consumption
  - 6W maximum via 802.3af Power-over-Ethernet
- Ethernet
  - IP101G PHY
  - 10/100 Mbit twisted pair copper
  - IEEE 802.3af Power-over-Ethernet
