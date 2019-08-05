# send_arp


## ARP
  ### 개요
  * ARP Protocol : 네트워크 상에서 IP주소와 MAC Address를 매치시키기 위해 사용하는 프로토콜이다. 
  <br>상대 컴퓨터의 IP만을 알고 있을떄 ARP를 날리면 상대 PC이 MAC Address를 알 수 있다.

  ### Header Structure
  ![](https://t1.daumcdn.net/cfile/tistory/2128E13C58EAF44D35)
  
  > * Hardware Type (HTYPE) : 네트워크 유형을 정의하며, Ethernet 환경의 경우 0x0001 으로 세팅
  > * Protocol Type (PTYPE) : 프로토콜을 정의하며, IP 프로토콜 버전4(IPv4)의 경우 0x0800 세팅
  > * Hardware Address Length (HLEN) : MAC주소의 길이를 정의하며, Ethernet 환경의 경우 6 byte 세팅
  > * Protocol Address Length (PLEN) : 프로토콜의 길이를 정의하며, IPv4 의 경우 4 byte 세팅
  > * Opcode : 패킷의 유형이며, ARP 요청(ARP Request)의 경우 1, ARP 응답 (ARP Reply)의 경우 2 세팅
  > * Sender Hardware Address (SHA) : 발신자의 MAC 주소 세팅
  > * Sender Protocol Address (SPA) : 발신자 IP 주소 세팅
  > * Destination Hardware Address (THA) : 목적지 MAC 주소, 그러나 ARP Request 의 경우 알 수 없음
  > * Destination Protocol Address (TPA) : 목적지 IP 주소 세팅
  
## ARP Spoofing
