/* 
  Check the new incoming messages, and print via serialin 115200 baud rate.
  
  by Aaron.Lee from HelTec AutoMation, ChengDu, China
  成都惠利特自动化科技有限公司
  www.heltec.cn
  
  this project also realess in GitHub:
  https://github.com/Heltec-Aaron-Lee/WiFi_Kit_series
*/

#include "heltec.h"
#define BAND    903900000  //you can set band here directly,e.g. 868E6,915E6
#define SYNCWORD 0x34
#define SF 7
#define BW 125000
void setup() {
    //WIFI Kit series V1 not support Vext control
  Heltec.begin(true /*DisplayEnable Enable*/, true /*Heltec.LoRa Disable*/, true /*Serial Enable*/, true /*PABOOST Enable*/, BAND /*long BAND*/);
  LoRa.receive();
  LoRa.setSpreadingFactor(SF);
  LoRa.setSignalBandwidth(BW);
  LoRa.setSyncWord(SYNCWORD);
}

void loop() {
  // try to parse packet
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    // received a packet
    Serial.print("Received packet '");
    // read packet
    while (LoRa.available()) {
      byte b = LoRa.read();
      if (b < 16) {Serial.print("0");}
      Serial.printf("%x ",b);
    }
    Serial.print("'\n");
    // print RSSI of packet
    Serial.printf("RSSI %d\n", LoRa.packetRssi());
    Serial.printf("SNR %d\n", LoRa.packetSnr());
    Serial.printf("Bandwidth %d\n", BW);
    Serial.printf("Frequency %d\n", BAND);
    Serial.printf("Spreading Factor %d\n", SF);
  }
  
}
