/*
 * HoneypotLogging.cpp
 * 
 * Implementation of logging and Syslog functionality for PoE-Honeypot
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/PoE-Honeypot
 */

#include "HoneypotLogging.h"

// Syslog message constant definitions
const uint8_t syslogPri[] = "<36>";  // Facility 4 (Security), Severity 4 (Warn)
const uint8_t syslogSvcTCP[] = " TCP/";
const uint8_t syslogSvcUDP[] = " UDP/";
const uint8_t syslogSvcICMP[] = " ICMP/Type ";
const uint8_t syslogMsg[] = ": Connection from ";
const uint8_t syslogMsgICMP[] = ": Ping request from ";

// Constructor
HoneypotLogging::HoneypotLogging(const uint8_t* hostName, IPAddress localIP, IPAddress syslogSvr, uint16_t syslogPt,
                                 bool debug, uint16_t tcpHoldoff, uint16_t udpHoldoff, 
                                 uint16_t icmpHoldoff,
                                 WiFiUDP* syslog, NTP* ntp,
                                 bool useSMTPRelay, IPAddress smtpSvr, 
                                 uint16_t smtpPt, const char* smtpFromAddr, const char* smtpToAddr) {
  hostname = hostName;
  honeypotIP = localIP;
  syslogServer = syslogSvr;
  syslogPort = syslogPt;
  debugMode = debug;
  tcpHoldoffSeconds = tcpHoldoff;
  udpHoldoffSeconds = udpHoldoff;
  icmpHoldoffSeconds = icmpHoldoff;
  syslogUdp = syslog;
  ntpClient = ntp;
  
  // SMTP configuration
  useSMTP = useSMTPRelay;
  smtpServer = smtpSvr;
  smtpPort = smtpPt;
  smtpFrom = smtpFromAddr;
  smtpTo = smtpToAddr;
  
  // Initialize queue indices
  logQueueHead = 0;
  logQueueTail = 0;
  
  // Initialize log indices
  tcpIPLogIndex = 0;
  udpIPLogIndex = 0;
  icmpIPLogIndex = 0;
  
  // Initialize SMTP async task members
  emailQueue = NULL;
  smtpTaskHandle = NULL;
}

// Destructor - cleanup FreeRTOS resources
HoneypotLogging::~HoneypotLogging() {
  // Stop SMTP task if running
  if (smtpTaskHandle != NULL) {
    vTaskDelete(smtpTaskHandle);
    smtpTaskHandle = NULL;
  }
  
  // Delete email queue if created
  if (emailQueue != NULL) {
    vQueueDelete(emailQueue);
    emailQueue = NULL;
  }
  
  // Delete serial mutex if created
  if (serialMutex != NULL) {
    vSemaphoreDelete(serialMutex);
    serialMutex = NULL;
  }
}

// Initialize logging system
void HoneypotLogging::begin() {
  // Create mutex for serial synchronization across cores
  serialMutex = xSemaphoreCreateMutex();
  
  // Initialize IP tracking arrays
  for(int i = 0; i < MAX_TRACKED_IPS; i++) {
    tcpIPLog[i].ip = 0;
    tcpIPLog[i].lastLogTime = 0;
    udpIPLog[i].ip = 0;
    udpIPLog[i].lastLogTime = 0;
    icmpIPLog[i].ip = 0;
    icmpIPLog[i].lastLogTime = 0;
  }
  
  // Initialize log queue
  for(int i = 0; i < LOG_QUEUE_SIZE; i++) {
    logQueue[i].valid = false;
  }
  
  // Start SMTP async task if SMTP is enabled
  beginSMTPTask();
}

// Thread-safe Serial functions
void HoneypotLogging::safePrint(const char* msg) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.print(msg);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrintln(const char* msg) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.println(msg);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrint(unsigned long val) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.print(val);
  xSemaphoreGive(serialMutex);
}

void HoneypotLogging::safePrintln(unsigned long val) {
  xSemaphoreTake(serialMutex, portMAX_DELAY);
  Serial.println(val);
  xSemaphoreGive(serialMutex);
}

// Initialize SMTP async task
void HoneypotLogging::beginSMTPTask() {
  // Only start if SMTP is enabled
  if (!useSMTP) {
    return;
  }
  
  // Create FreeRTOS queue for 8 pending emails
  emailQueue = xQueueCreate(8, sizeof(EmailQueueEntry));
  
  if (emailQueue == NULL) {
    if (debugMode) {
      safePrintln("[DEBUG] ERROR: Failed to create email queue");
    }
    return;
  }
  
  // Create SMTP task on core 0 (core 1 runs main loop)
  // Stack: 8KB, Priority: 1 (low), Pinned to core 0
  BaseType_t result = xTaskCreatePinnedToCore(
    smtpTask,           // Task function
    "SMTP_Task",        // Task name
    8192,               // Stack size (8KB)
    this,               // Parameter (this object)
    1,                  // Priority (low)
    &smtpTaskHandle,    // Task handle
    0                   // Core 0 (main loop on core 1)
  );
  
  if (result != pdPASS) {
    if (debugMode) {
      safePrintln("[DEBUG] ERROR: Failed to create SMTP task");
    }
    // Clean up queue if task creation failed
    vQueueDelete(emailQueue);
    emailQueue = NULL;
  }
}

// SMTP task function - runs on core 0, processes emails from queue
void HoneypotLogging::smtpTask(void* parameter) {
  HoneypotLogging* logger = (HoneypotLogging*)parameter;
  EmailQueueEntry email;
  
  if (logger->debugMode) {
    logger->safePrintln("[DEBUG] SMTP task running");
  }
  
  // Process emails from queue indefinitely
  while (true) {
    // Wait for email (blocks this task, not main loop)
    // portMAX_DELAY = wait indefinitely
    if (xQueueReceive(logger->emailQueue, &email, portMAX_DELAY) == pdTRUE) {
      // Send email (blocks this task, main loop continues)
      logger->sendSMTPEmail(email.subject, email.body);
      
      // Small delay between emails
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  }
}

// Queue email for async sending (non-blocking)
bool HoneypotLogging::queueEmail(const char* subject, const char* body) {
  // Fail silently if SMTP not enabled or queue not created
  if (!useSMTP || emailQueue == NULL) {
    return false;
  }
  
  // Prepare email entry
  EmailQueueEntry email;
  strncpy(email.subject, subject, sizeof(email.subject) - 1);
  email.subject[sizeof(email.subject) - 1] = '\0';
  strncpy(email.body, body, sizeof(email.body) - 1);
  email.body[sizeof(email.body) - 1] = '\0';
  
  // Non-blocking send to queue
  if (xQueueSend(emailQueue, &email, 0) == pdTRUE) {
    if (debugMode) {
      safePrintln("[DEBUG] Email queued for async sending");
    }
    return true;
  } else {
    // Queue is full, drop email
    if (debugMode) {
      safePrintln("[DEBUG] WARNING: Email queue full, dropping email");
    }
    return false;
  }
}

// Enqueue event for main loop processing
// Called from lwIP task context (not hardware ISR), uses critical sections
bool HoneypotLogging::enqueueLogEvent(uint16_t portOrType, uint32_t sourceIP, ProtocolType protocol, const char* serviceName) {
  // SECURITY: Enter critical section to prevent race conditions with processLogQueue
  portENTER_CRITICAL(&queueMux);
  
  uint8_t nextHead = (logQueueHead + 1) % LOG_QUEUE_SIZE;
  
  // Check if queue is full
  if (nextHead == logQueueTail) {
    portEXIT_CRITICAL(&queueMux);
    return false; // Queue full, drop event
  }
  
  // Add event to queue
  logQueue[logQueueHead].portOrType = portOrType;
  logQueue[logQueueHead].sourceIP = sourceIP;
  logQueue[logQueueHead].protocol = protocol;
  logQueue[logQueueHead].serviceName = serviceName;
  logQueue[logQueueHead].valid = true;
  
  logQueueHead = nextHead;
  
  portEXIT_CRITICAL(&queueMux);
  return true;
}

// Process queued events from main loop
void HoneypotLogging::processLogQueue(IPAddress localIP, IPAddress subnetMask) {
  while (logQueueTail != logQueueHead) {
    // SECURITY: Enter critical section to safely read queue entry
    portENTER_CRITICAL(&queueMux);
    
    LogQueueEntry* entry = &logQueue[logQueueTail];
    
    // Copy data out of queue while in critical section
    bool isValid = entry->valid;
    uint16_t portOrType = entry->portOrType;
    uint32_t sourceIP_u32 = entry->sourceIP;
    ProtocolType protocol = entry->protocol;
    const char* serviceName = entry->serviceName;
    
    // Mark as processed and advance tail
    entry->valid = false;
    logQueueTail = (logQueueTail + 1) % LOG_QUEUE_SIZE;
    
    portEXIT_CRITICAL(&queueMux);
    
    // Process event outside critical section (avoid holding lock during I/O)
    if (isValid) {
      // Check if broadcast/multicast first (silently filter)
      if (isBroadcastOrMulticast(sourceIP_u32, localIP, subnetMask)) {
        continue; // Skip without logging
      }
      
      // Check holdoff - log if in holdoff period and DEBUG enabled
      if (!shouldLogEvent(sourceIP_u32, protocol)) {
        if (debugMode) {
          IPAddress sourceIP(sourceIP_u32);
          char debugMsg[120];
          const char* protoName = (protocol == PROTO_ICMP) ? "ICMP Type" : 
                                  (protocol == PROTO_UDP) ? "UDP" : "TCP";
          snprintf(debugMsg, sizeof(debugMsg), "[DEBUG] %s %u (%s) <- %d.%d.%d.%d (IN HOLDOFF - IGNORING)", 
                   protoName, portOrType, serviceName, sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);
          safePrintln(debugMsg);
        }
        continue; // Skip logging
      }
      
      // Not in holdoff, log the event
      IPAddress sourceIP(sourceIP_u32);
      logEvent(portOrType, sourceIP, protocol, serviceName);
    }
  }
}

// Detect broadcast or multicast IPs
// Returns true if IP should be filtered
bool HoneypotLogging::isBroadcastOrMulticast(uint32_t source_ip, IPAddress localIP, IPAddress subnetMask) {
  // Extract octets from network byte order IP
  uint8_t octet1 = (source_ip & 0xFF);
  uint8_t octet2 = (source_ip >> 8) & 0xFF;
  uint8_t octet3 = (source_ip >> 16) & 0xFF;
  uint8_t octet4 = (source_ip >> 24) & 0xFF;
  
  // Check for limited broadcast (255.255.255.255)
  if (source_ip == 0xFFFFFFFF) {
    return true;
  }
  
  // Check for multicast addresses (224.0.0.0/4 - first octet 224-239)
  if (octet1 >= 224 && octet1 <= 239) {
    return true;
  }
  
  // Check for local network broadcast based on configured subnet
  uint32_t local_ip = ((uint32_t)localIP[0]) | ((uint32_t)localIP[1] << 8) | 
                      ((uint32_t)localIP[2] << 16) | ((uint32_t)localIP[3] << 24);
  uint32_t subnet_mask = ((uint32_t)subnetMask[0]) | ((uint32_t)subnetMask[1] << 8) | 
                         ((uint32_t)subnetMask[2] << 16) | ((uint32_t)subnetMask[3] << 24);
  uint32_t network_broadcast = (local_ip & subnet_mask) | (~subnet_mask);
  
  if (source_ip == network_broadcast) {
    return true;
  }
  
  // Check for link-local broadcast (169.254.255.255)
  if (octet1 == 169 && octet2 == 254 && octet3 == 255 && octet4 == 255) {
    return true;
  }
  
  return false;
}

// Check holdoff to prevent event flooding
// Returns true if event should be logged
bool HoneypotLogging::shouldLogEvent(uint32_t ip, ProtocolType protocol) {
  IPLogEntry* logArray;
  uint8_t* logIndex;
  uint16_t holdoffSeconds;
  
  // Select appropriate tracking array and holdoff time
  switch(protocol) {
    case PROTO_TCP:
      logArray = tcpIPLog;
      logIndex = &tcpIPLogIndex;
      holdoffSeconds = tcpHoldoffSeconds;
      break;
    case PROTO_UDP:
      logArray = udpIPLog;
      logIndex = &udpIPLogIndex;
      holdoffSeconds = udpHoldoffSeconds;
      break;
    case PROTO_ICMP:
      logArray = icmpIPLog;
      logIndex = &icmpIPLogIndex;
      holdoffSeconds = icmpHoldoffSeconds;
      break;
    default:
      return true;
  }
  
  // Holdoff disabled, always log
  if (holdoffSeconds == 0) {
    return true;
  }
  
  unsigned long currentTime = millis();
  unsigned long holdoffMillis = (unsigned long)holdoffSeconds * 1000;
  
  // Search for IP in tracking array
  for(int i = 0; i < MAX_TRACKED_IPS; i++) {
    if(logArray[i].ip == ip) {
      // Check if holdoff expired
      if(currentTime - logArray[i].lastLogTime >= holdoffMillis) {
        // Update timestamp and allow logging
        logArray[i].lastLogTime = currentTime;
        return true;
      } else {
        // Still in holdoff period
        return false;
      }
    }
  }
  
  // IP not tracked yet, add it
  logArray[*logIndex].ip = ip;
  logArray[*logIndex].lastLogTime = currentTime;
  *logIndex = (*logIndex + 1) % MAX_TRACKED_IPS; // Circular buffer
  
  return true;
}

// Combined IP filtering (broadcast/multicast + holdoff)
bool HoneypotLogging::shouldLogIP(uint32_t sourceIP, ProtocolType protocol, 
                                   IPAddress localIP, IPAddress subnetMask) {
  // Filter broadcast/multicast
  if (isBroadcastOrMulticast(sourceIP, localIP, subnetMask)) {
    return false;
  }
  
  // Check holdoff
  return shouldLogEvent(sourceIP, protocol);
}

// Send email via SMTP relay
bool HoneypotLogging::sendSMTPEmail(const char* subject, const char* body) {
  if (debugMode) {
    safePrintln("[DEBUG] Connecting to SMTP server...");
  }
  
  // Set timeout (5s for reads/writes, 3s for connect)
  smtpClient.setTimeout(5);
  
  // Connect to server
  unsigned long connectStart = millis();
  if (!smtpClient.connect(smtpServer, smtpPort)) {
    unsigned long connectDuration = millis() - connectStart;
    if (debugMode) {
      char msg[100];
      snprintf(msg, sizeof(msg), "[DEBUG] ERROR: Failed to connect to SMTP server after %lu ms", connectDuration);
      safePrintln(msg);
    }
    return false;
  }
  
  if (debugMode) {
    unsigned long connectDuration = millis() - connectStart;
    char msg[100];
    snprintf(msg, sizeof(msg), "[DEBUG] Connected to SMTP server in %lu ms", connectDuration);
    safePrintln(msg);
  }
  
  // Wait for server greeting
  unsigned long timeout = millis();
  while (smtpClient.available() == 0) {
    if (millis() - timeout > 5000) {
      if (debugMode) {
        safePrintln("[DEBUG] ERROR: SMTP server timeout");
      }
      smtpClient.stop();
      return false;
    }
    delay(10);
  }
  
  // Read and discard greeting
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // Send HELO
  smtpClient.print("HELO ");
  smtpClient.println((const char*)hostname);
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // MAIL FROM
  smtpClient.print("MAIL FROM:<");
  smtpClient.print(smtpFrom);
  smtpClient.println(">");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // RCPT TO
  smtpClient.print("RCPT TO:<");
  smtpClient.print(smtpTo);
  smtpClient.println(">");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // DATA command
  smtpClient.println("DATA");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // Email headers
  smtpClient.print("From: ");
  smtpClient.println(smtpFrom);
  smtpClient.print("To: ");
  smtpClient.println(smtpTo);
  smtpClient.print("Subject: ");
  smtpClient.println(subject);
  smtpClient.println("Content-Type: text/plain; charset=utf-8");
  smtpClient.println();
  
  // Email body
  smtpClient.println(body);
  
  // End with CRLF.CRLF
  smtpClient.println(".");
  delay(100);
  while (smtpClient.available()) {
    smtpClient.read();
  }
  
  // QUIT
  smtpClient.println("QUIT");
  delay(100);
  
  smtpClient.stop();
  
  if (debugMode) {
    safePrintln("[DEBUG] Email sent successfully");
  }
  
  return true;
}

// Build and send syslog event
void HoneypotLogging::logEvent(uint16_t portOrType, IPAddress sourceIP, ProtocolType protocol, const char* serviceName) {
  // Get formatted timestamp
  const char* timeStr = ntpClient->formattedTime("%b %d %T ");
  size_t timeLen = strlen(timeStr);
  if (timeLen > 16) timeLen = 16;
  
  // Create properly sized buffer for DTS (including space for null terminator)
  uint8_t DTS[17];
  memcpy(DTS, timeStr, timeLen);
  DTS[timeLen] = '\0';
  
  // Debug output
  if (debugMode) {
    char debugMsg[100];
    const char* protoName = (protocol == PROTO_ICMP) ? "ICMP Type" : 
                            (protocol == PROTO_UDP) ? "UDP" : "TCP";
    snprintf(debugMsg, sizeof(debugMsg), "[DEBUG] %s %u (%s) <- %d.%d.%d.%d", 
             protoName, portOrType, serviceName, sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);
    safePrintln(debugMsg);
  }
  
  // Convert port/type to string
  char valueString[6] = "";
  itoa(portOrType, valueString, 10);
  
  // Convert IP to string
  char ipString[16];
  snprintf(ipString, sizeof(ipString), "%d.%d.%d.%d", 
           sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3]);
  
  // SMTP mode: send email instead
  if (useSMTP) {
    // Build email subject
    char subject[80];
    const char* protoName = (protocol == PROTO_ICMP) ? "ICMP" : 
                            (protocol == PROTO_UDP) ? "UDP" : "TCP";
    snprintf(subject, sizeof(subject), "[%s Alert] Honeypot traffic detected (%s)", 
             (const char*)hostname, protoName);
    
    // Build email body with service name
    char body[384];
    if (protocol == PROTO_ICMP) {
      snprintf(body, sizeof(body), 
               "Honeypot: %s (%d.%d.%d.%d)\nTimestamp: %s UTC\nSource IP: %s\nProtocol: ICMP\nType: %u (%s)\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               (const char*)DTS, ipString, portOrType, serviceName);
    } else {
      snprintf(body, sizeof(body), 
               "Honeypot: %s (%d.%d.%d.%d)\nTimestamp: %s UTC\nSource IP: %s\nProtocol: %s\nPort: %u (%s)\n",
               (const char*)hostname, honeypotIP[0], honeypotIP[1], honeypotIP[2], honeypotIP[3],
               (const char*)DTS, ipString, protoName, portOrType, serviceName);
    }
    
    if (debugMode) {
      safePrintln("[DEBUG] Queueing email alert for async sending...");
    }
    
    // Queue for async send
    queueEmail(subject, body);
    return;
  }
  
  // Syslog mode
  // Select format strings based on protocol
  const uint8_t* syslogSvc;
  const uint8_t* syslogMessage;
  int svcLen;
  
  if (protocol == PROTO_ICMP) {
    syslogSvc = syslogSvcICMP;
    svcLen = sizeof(syslogSvcICMP);
    syslogMessage = syslogMsgICMP;
  } else if (protocol == PROTO_UDP) {
    syslogSvc = syslogSvcUDP;
    svcLen = sizeof(syslogSvcUDP);
    syslogMessage = syslogMsg;
  } else { // PROTO_TCP
    syslogSvc = syslogSvcTCP;
    svcLen = sizeof(syslogSvcTCP);
    syslogMessage = syslogMsg;
  }
  
  int hostnameLen = strlen((const char*)hostname);
  int serviceLen = strlen(serviceName);
  
  // Calculate message size
  // Format: "TCP/22 (ssh):" or "ICMP/Type 8 (echo-request):"
  int eventBytes = (sizeof(syslogPri) - 1 + timeLen + hostnameLen + 
                    svcLen - 1 + strlen(valueString) + 
                    3 + serviceLen + // " (" + serviceName + ")"
                    strlen((const char*)syslogMessage) + 
                    strlen(ipString));
  
  // Validate size to prevent overflow
  if (eventBytes < 0 || eventBytes > 512) {
    if (debugMode) {
      safePrintln("[DEBUG] ERROR: Syslog message too large, skipping");
    }
    return;
  }
  
  uint8_t eventData[eventBytes];

  // Build syslog message
  int offset = 0;
  memcpy(eventData + offset, syslogPri, sizeof(syslogPri)-1);
  offset += sizeof(syslogPri)-1;
  memcpy(eventData + offset, DTS, timeLen);
  offset += timeLen;
  memcpy(eventData + offset, hostname, hostnameLen);
  offset += hostnameLen;
  memcpy(eventData + offset, syslogSvc, svcLen-1);
  offset += svcLen-1;
  memcpy(eventData + offset, valueString, strlen(valueString));
  offset += strlen(valueString);
  
  // Add service name: " (service)"
  eventData[offset++] = ' ';
  eventData[offset++] = '(';
  memcpy(eventData + offset, serviceName, serviceLen);
  offset += serviceLen;
  eventData[offset++] = ')';
  
  memcpy(eventData + offset, syslogMessage, strlen((const char*)syslogMessage));
  offset += strlen((const char*)syslogMessage);
  memcpy(eventData + offset, ipString, strlen(ipString));

  // Debug: print formatted message
  if (debugMode) {
    // Build message atomically to prevent interleaving
    char debugBuffer[600];
    strcpy(debugBuffer, "[DEBUG] Syslog: ");
    int prefixLen = strlen(debugBuffer);
    
    // Copy as printable characters
    for (int i = 0; i < eventBytes && (prefixLen + i) < (sizeof(debugBuffer) - 1); i++) {
      debugBuffer[prefixLen + i] = eventData[i];
    }
    debugBuffer[prefixLen + eventBytes] = '\0';
    
    safePrintln(debugBuffer);
  }

  // Send syslog message
  syslogUdp->beginPacket(syslogServer, syslogPort);
  syslogUdp->write(eventData, eventBytes);
  syslogUdp->endPacket();
}
