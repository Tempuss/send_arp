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
  ![image](https://user-images.githubusercontent.com/13353498/62436635-346e1200-b77b-11e9-8d84-fffb42b17ed3.png)

  ### 시나리오
  * 공격자는 GateWay, Sender의 IP를 알고 있다
  * 단어 설명 
    > * Attacker : 본인 PC(공격자)
    > * Sender : 피해자 PC(피해자) aka Destination
    > * Target : GateWay
  
  * Attacker
    - IP : 192.168.43.139
    - MAC : 04-EA-56-20-BC-F5
    
  * Sender
    - IP : 192.168.43.234
    - MAC : 04-EA-56-20-E2-75
    
  * Target
    - IP : 192.168.43.1
    - MAC : 66-7b-ce-98-62-e8
  
  #### 순서
  1. 네트워크 전체에 BroadCast로 43.234에 ARP Request를 날린다
  
  2. ARP Reply로 받은 packet에서 43.234에 대한 MAC Address를 가져온다
  
  3. 43.234에게 Sender Protocol Address를 43.1을 넣고 Sender Hardware Address에 공격자의 MAC Address를 넣고 ARP Reply를 날린다
  
  4. ARP Reply를 받은 Sender PC는 ARP 테이블을 업데이트 하여 공격자의 MAC Address를 GateWay로 착각하게 되낟
  
