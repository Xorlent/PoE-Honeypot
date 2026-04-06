/*
 * HoneypotLogging.h
 * 
 * Logging and Syslog functionality for PoE-Honeypot
 * Handles event queuing, holdoff tracking, and syslog message formatting
 *
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/PoE-Honeypot
 */

#ifndef HONEYPOT_LOGGING_H
#define HONEYPOT_LOGGING_H

#include <Arduino.h>
#include "Config.h"

// Compile-time validation of MAX_TRACKED_IPS
static_assert(MAX_TRACKED_IPS > 0, "MAX_TRACKED_IPS must be greater than 0");
static_assert(MAX_TRACKED_IPS <= 255, "MAX_TRACKED_IPS must not exceed 255");
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <NTP.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

// Protocol types for unified logging
enum ProtocolType {
  PROTO_TCP,
  PROTO_UDP,
  PROTO_ICMP
};

// Event queue entry structure for deferred logging
struct LogQueueEntry {
  uint16_t portOrType;
  uint32_t sourceIP;
  ProtocolType protocol;
  const char* serviceName;
  bool valid;
};

// IP tracking structure for holdoff functionality
struct IPLogEntry {
  uint32_t ip;
  unsigned long lastLogTime;
};

// Email queue entry structure for async SMTP processing
struct EmailQueueEntry {
  char subject[80];
  char body[384];
};

// Syslog message constants
extern const uint8_t syslogPri[];
extern const uint8_t syslogSvcTCP[];
extern const uint8_t syslogSvcUDP[];
extern const uint8_t syslogSvcICMP[];
extern const uint8_t syslogMsg[];
extern const uint8_t syslogMsgICMP[];

// Log queue configuration
#define LOG_QUEUE_SIZE 16

// Class for managing honeypot logging functionality
class HoneypotLogging {
private:
  // Queue for deferred event processing
  LogQueueEntry logQueue[LOG_QUEUE_SIZE];
  volatile uint8_t logQueueHead;
  volatile uint8_t logQueueTail;
  
  // SECURITY: Spinlock for queue access (protects against race conditions)
  #ifdef ESP32
    portMUX_TYPE queueMux = portMUX_INITIALIZER_UNLOCKED;
  #endif
  
  // FreeRTOS mutex for inter-core Serial synchronization
  SemaphoreHandle_t serialMutex;

  IPLogEntry tcpIPLog[MAX_TRACKED_IPS];
  IPLogEntry udpIPLog[MAX_TRACKED_IPS];
  IPLogEntry icmpIPLog[MAX_TRACKED_IPS];
  uint8_t tcpIPLogIndex;
  uint8_t udpIPLogIndex;
  uint8_t icmpIPLogIndex;
  
  // Configuration
  const uint8_t* hostname;
  IPAddress honeypotIP;
  IPAddress syslogServer;
  uint16_t syslogPort;
  bool debugMode;
  uint16_t tcpHoldoffSeconds;
  uint16_t udpHoldoffSeconds;
  uint16_t icmpHoldoffSeconds;
  
  // SMTP configuration
  bool useSMTP;
  IPAddress smtpServer;
  uint16_t smtpPort;
  const char* smtpFrom;
  const char* smtpTo;
  
  // External dependencies
  WiFiUDP* syslogUdp;
  NTP* ntpClient;
  WiFiClient smtpClient;
  
  // SMTP async task support
  QueueHandle_t emailQueue;
  TaskHandle_t smtpTaskHandle;
  static void smtpTask(void* parameter);
  
  // Helper methods
  bool isBroadcastOrMulticast(uint32_t source_ip, IPAddress localIP, IPAddress subnetMask);
  bool shouldLogEvent(uint32_t ip, ProtocolType protocol);
  bool sendSMTPEmail(const char* subject, const char* body);
  
public:
  // Constructor
  HoneypotLogging(const uint8_t* hostName, IPAddress localIP, IPAddress syslogSvr, uint16_t syslogPt,
                  bool debug, uint16_t tcpHoldoff, uint16_t udpHoldoff, uint16_t icmpHoldoff,
                  WiFiUDP* syslog, NTP* ntp,
                  bool useSMTPRelay = false, IPAddress smtpSvr = IPAddress(0,0,0,0), 
                  uint16_t smtpPt = 25, const char* smtpFromAddr = "", const char* smtpToAddr = "");
  
  // Destructor - cleanup FreeRTOS resources
  ~HoneypotLogging();
  
  // Initialization
  void begin();
  
  // Thread-safe Serial printing
  void safePrint(const char* msg);
  void safePrintln(const char* msg);
  void safePrint(unsigned long val);
  void safePrintln(unsigned long val);
  
  // SMTP async methods
  void beginSMTPTask();
  bool queueEmail(const char* subject, const char* body);
  
  // Event queuing (lwIP task context, uses critical sections)
  bool enqueueLogEvent(uint16_t portOrType, uint32_t sourceIP, ProtocolType protocol, const char* serviceName = "unknown");
  
  // Event processing (main loop)
  void processLogQueue(IPAddress localIP, IPAddress subnetMask);
  
  // Logging
  void logEvent(uint16_t portOrType, IPAddress sourceIP, ProtocolType protocol, const char* serviceName = "unknown");
  
  // IP filtering
  bool shouldLogIP(uint32_t sourceIP, ProtocolType protocol, IPAddress localIP, IPAddress subnetMask);
};

#endif // HONEYPOT_LOGGING_H
