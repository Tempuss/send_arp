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

  ### Network Structure 
  ![image](https://user-images.githubusercontent.com/13353498/62453502-69935800-b7ad-11e9-8849-10b13efd2fc8.png)


  ### 시나리오
  * 공격자는 GateWay, Sender의 IP를 알고 있다
  * 단어 설명 
    > * Attacker : 본인 PC(공격자)
    > * Sender : 피해자 PC(피해자) aka Destination
    > * Target : GateWay
  
  * Attacker
    - IP : 10.0.2.4
    - MAC :08:00:27:6d:8f:be
    
  * Sender
    - IP : 10.0.2.6
    - MAC : 08:00:27:54:8f:b5
      
  * Target
    - IP : 10.0.2.1
    - MAC : 52:54:00:12:35:00
    
  
  ### 순서
  #### 1. 네트워크 전체에 BroadCast로 10.0.2.6에 ARP Request를 날린다
  ![normal_arp_request](https://user-images.githubusercontent.com/13353498/62453653-b9721f00-b7ad-11e9-97f1-0b66c8a5e1dc.PNG)
  
  #### 2. ARP Reply로 받은 packet에서 10.0.2.6에 대한 MAC Address를 가져온다
  ![normal_arp_reply](https://user-images.githubusercontent.com/13353498/62453663-becf6980-b7ad-11e9-98fd-ff12f8c2a751.PNG)
  
  #### 3. 10.0.2.6에게 Sender Protocol Address를 10.0.2.1을 넣고 Sender Hardware Address에 공격자의 MAC Address를 넣고 ARP Reply를 날린다
  ![mal_arp_reply](https://user-images.githubusercontent.com/13353498/62453665-becf6980-b7ad-11e9-8e8a-80f76954929c.PNG)
  
  #### 4. ARP Reply를 받은 Sender PC는 ARP 테이블을 업데이트 하여 공격자의 MAC Address를 GateWay로 착각하게 된다
  ![after_attack](https://user-images.githubusercontent.com/13353498/62453710-d9094780-b7ad-11e9-9514-73fc7856f8ea.PNG)
