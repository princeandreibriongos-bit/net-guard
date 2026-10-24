/**
 * ==============================================================================
 * NET-GUARD: ESP32 + DHT11 Edge IoT Sensor Telemetry Firmware
 * ==============================================================================
 * Hardware Components:
 *   1. ESP32 Development Board (ESP-WROOM-32 / NodeMCU-32S)
 *   2. DHT11 Temperature & Relative Humidity Sensor
 *
 * Pin Connections:
 *   - DHT11 VCC   -> ESP32 3.3V (or 5V depending on sensor module)
 *   - DHT11 GND   -> ESP32 GND
 *   - DHT11 DATA  -> ESP32 GPIO 4 (D4) with 10k pull-up resistor to 3.3V
 *
 * Target Network Deployment:
 *   - The ESP32 joins the local IoT Wi-Fi subnet.
 *   - Broadcasts JSON UDP telemetry packets to Port 5005 every 2 seconds.
 *   - The TP-Link TL-SG105E managed switch mirrors this traffic to the NIDS host.
 * ==============================================================================
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <DHT.h>

// ==============================================================================
// CONFIGURATION
// ==============================================================================
#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"

// NIDS Ingestion Host or Subnet Broadcast (e.g. 192.168.1.255)
#define TARGET_IP       "192.168.1.255"
#define UDP_PORT        5005
#define NODE_ID         "esp32-node-01"
#define SAMPLE_INTERVAL 2000   // 2.0 seconds in milliseconds

#define DHT_PIN         4      // GPIO 4
#define DHT_TYPE        DHT11  // DHT 11

// Instances
DHT dht(DHT_PIN, DHT_TYPE);
WiFiUDP udp;

unsigned long lastSampleTime = 0;
uint32_t sequenceNumber = 0;

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n[NET-GUARD] ESP32 Telemetry Node Booting...");

  // Initialize DHT Sensor
  dht.begin();

  // Connect to Wi-Fi
  Serial.print("[WiFi] Connecting to: ");
  Serial.println(WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n[WiFi] Connected!");
  Serial.print("[WiFi] IP Address : ");
  Serial.println(WiFi.localIP());
  Serial.print("[WiFi] MAC Address: ");
  Serial.println(WiFi.macAddress());

  udp.begin(UDP_PORT);
  Serial.println("[UDP] Telemetry broadcast active on port 5005.\n");
}

void loop() {
  // Reconnect Wi-Fi if dropped
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] Lost connection. Reconnecting...");
    WiFi.reconnect();
    delay(2000);
    return;
  }

  unsigned long now = millis();
  if (now - lastSampleTime >= SAMPLE_INTERVAL) {
    lastSampleTime = now;
    sequenceNumber++;

    // Read DHT11
    float humidity = dht.readHumidity();
    float temperature = dht.readTemperature(); // Celsius

    // Handle sensor read failures
    if (isnan(humidity) || isnan(temperature)) {
      Serial.println("[DHT11] Warning: Failed to read from sensor!");
      return;
    }

    // Format JSON Telemetry Payload
    char payload[256];
    snprintf(
      payload,
      sizeof(payload),
      "{\"device_id\":\"%s\",\"seq\":%u,\"timestamp\":%lu,\"sensor\":\"DHT11\",\"temp\":%.2f,\"humidity\":%.2f,\"status\":\"HEALTHY\"}",
      NODE_ID,
      sequenceNumber,
      now,
      temperature,
      humidity
    );

    // Broadcast UDP Packet
    udp.beginPacket(TARGET_IP, UDP_PORT);
    udp.write((const uint8_t*)payload, strlen(payload));
    udp.endPacket();

    Serial.print("[TX] Seq #");
    Serial.print(sequenceNumber);
    Serial.print(" | Temp: ");
    Serial.print(temperature, 1);
    Serial.print(" °C | Hum: ");
    Serial.print(humidity, 1);
    Serial.println(" %");
  }
}
