/*
 *  VUT FIT IPK Projekt 2 (packet sniffer)
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <string.h>
#include "time.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
struct my_ip {
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src,ip_dst;	/* source and dest address */
};
u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Zpracuje ip hlavičku (vypíše src ip a dest ip)
     * a pokud následuje TCP nebo UDP tak vypíše porty
     * */
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
        fprintf(stdout,"Unknown version %d\n",version);
        return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        //fprintf(stdout,"IP: ");
        fprintf(stdout,"src IP: %s\n", inet_ntoa(ip->ip_src));
        //fprintf(stdout,"%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen,version,len,off);
        fprintf(stdout,"dst IP: %s\n", inet_ntoa(ip->ip_dst));

    }
    if(ip->ip_p == 6) //6 je TCP
    {
        const struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
        //fprintf(stdout,"src port: %s \n",ether_ntoa((struct ether_addr*)eptr->ether_shost));
        printf("src port: %d\n", ntohs(tcp->th_sport));
        printf("dst port: %d\n", ntohs(tcp->th_dport));
    }else if(ip->ip_p == 17) //UDP
    {
        const struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
        printf("src port: %d\n", ntohs(udp->uh_sport));
        printf("dst port: %d\n", ntohs(udp->uh_dport));
    }else if(ip->ip_p == 1) //ICMP
    {
        //Nemá porty k vypsání
        ;
    }
    return NULL;
}
u_char* handle_IPv6(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* https://stackoverflow.com/questions/38848281/inet-ntop-printing-incorrect-ipv6-address
     * Autor Brian Sidebotham Aug 9, 2016
     * Načtení a převedení ipv6 na string
     * */

    struct ip6_hdr *ip = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip->ip6_src, addr, INET6_ADDRSTRLEN);
    fprintf(stdout,"src IP: %s\n", addr);
    inet_ntop(AF_INET6, &ip->ip6_dst, addr, INET6_ADDRSTRLEN);
    fprintf(stdout,"dst IP: %s\n", addr);
    if(ip->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) //6 je TCP
    {
        const struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        printf("src port: %d\n", ntohs(tcp->th_sport));
        printf("dst port: %d\n", ntohs(tcp->th_dport));
    }else if(ip->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) //UDP
    {
        const struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        printf("src port: %d\n", ntohs(udp->uh_sport));
        printf("dst port: %d\n", ntohs(udp->uh_dport));
    }else if(ip->ip6_ctlun.ip6_un1.ip6_un1_nxt == 1) //ICMP
    {
        //Není potřeba dále zpracovávat
    }
}
void PrintData (const u_char * data , int Size)
{
    /*https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
     * Autor Silver Moon | 5. září 2020
     * Použil jsem funkci PrintData ve které jsem změnil výstup na stdout,
     * nahradil mezeru na začátku řádku offsetem vypsaných bajtů
     * a doplnil mezery pro přehlednost
     * */
    int i , j = 0;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(stdout , "    ");
            for(j=i-16 ; j<i ; j++)
            {
                if((j%8 ==  0) && (j%16 != 0)) fprintf(stdout , " ");
                if(data[j]>=32 && data[j]<=128)
                    fprintf(stdout , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(stdout , "."); //otherwise print a dot
            }
            fprintf(stdout , "\n");
        }

        if(i%16==0) printf("0x%.3x0: ", j/16);//fprintf(stdout , "   ");
        if((i%8 ==  0) && (i%16 != 0)) fprintf(stdout , " ");
        fprintf(stdout , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            if(i%16 < 8) printf(" ");
            for(j=0;j<15-i%16;j++)
            {
                fprintf(stdout , "   "); //extra spaces
            }

            fprintf(stdout , "    ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if((j%8 ==  0) && (j%16 != 0)) fprintf(stdout , " ");
                if(data[j]>=32 && data[j]<=128)
                {
                    fprintf(stdout , "%c",(unsigned char)data[j]);
                }
                else
                {
                    fprintf(stdout , ".");
                }
            }

            fprintf(stdout ,  "\n" );
        }
    }
}
void Print_Interfaces(){
    /* http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
     * January 21, 2014
     * Výpis zařízení a ukončení programu
     * */
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if(pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Error in pcap findall devs\n");
        exit(-1);
    }
    for(temp = interfaces; temp; temp = temp->next)
    {
        printf("%s\n", temp->name);

    }
    exit(EXIT_SUCCESS);
}
u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Zpracuje ethernetovou hlavičku (vypíše timeshamp, src mac, dest mac, a délku)
     * a vrátí typ následující hlavičky
     * */
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDR_LEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    /* https://www.epochconverter.com/programming/c
     * Práce s časem v c
     * */
    time_t rawtime = pkthdr->ts.tv_sec;
    struct tm  ts;
    char buf[80];
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts);
    printf("timestamp: %s.%ld%c%02d:%02d\n", buf, pkthdr->ts.tv_usec / 1000, (ts.tm_gmtoff < 0) ? '-' : '+', (int)ts.tm_gmtoff / 3600, (int)ts.tm_gmtoff % 3600);
    fprintf(stdout,"src MAC: %s \n",ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"dst MAC: %s \n",ether_ntoa((struct ether_addr*)eptr->ether_dhost));
    fprintf(stdout,"frame length: %d bytes\n",length);
    return ether_type;
}
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Inspiroval jsem se s postupem zpracování
     * */
    u_int16_t type = handle_ethernet(args,pkthdr,packet);
    if(type == ETHERTYPE_IP)
    {/* handle IP packet */
        handle_IP(args,pkthdr,packet);
    }else if(type == ETHERTYPE_IPV6)
    {
        /* handle IPv6 packet */
        handle_IPv6(args,pkthdr,packet);
    }else if(type == ETHERTYPE_ARP)
    {
        //Není potřeba dále zpracovávat
    }
    PrintData(packet, pkthdr->len); //Funkce pro výpis dat
}

int main (int argc, char* argv[])
{
    int Port = 0;
    int n = 1; //defaultní hodnota počtu odchytávaných packtetů
    bool ParamI = 1; //Byl/nebyl zadán parametr i (0/1)
    bool Protocols [4]; //tcp, udp, arp, icmp
    for(int i = 0; i < 4; i++) Protocols[i] = 0;
    char filter_exp [100] = "";  /* The filter expression */
    char *dev; /* The device to sniff on */

    /* https://www.man7.org/linux/man-pages/man3/getopt.3.html
     * Author Michael Kerrisk 2021-08-27
     * Načtení a zpracování argumentů
     * */
    int c;
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
                {"interface",     optional_argument, 0,  'i' }, //interface
                {"tcp",           no_argument,       0,  't' },
                {"udp",           no_argument,       0,  'u' },
                {"arp",           no_argument,       0,  'a' },
                {"icmp",          no_argument,       0,  'b' },
                {0,       0,                 0,  0 }
        };
        c = getopt_long(argc, argv, "i::p:tun:",long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 'i': //interface
                ParamI = 0;
                /* https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
                 * Autor  Lars Erik Wik August 13, 2021
                 * Zpracování optional argumentu
                 * */
                if (optarg == NULL && optind < argc && argv[optind][0] != '-')
                {
                    optarg = argv[optind++];
                }
                if (optarg == NULL) Print_Interfaces();
                else dev = optarg;
                break;
            case 'p':
                if(optarg) //Nalezen argument
                {
                    if(atoi(optarg)) Port = atoi(optarg);
                    else {
                        printf("Převod čísla: \"%s\" selhal\n", optarg);
                        exit(2);
                    }
                }
                break;
            case 't':
                Protocols[0] = 1;
                break;
            case 'u':
                Protocols[1] = 1;
                break;
            case 'a':
                Protocols[2] = 1;
                break;
            case 'b':
                Protocols[3] = 1;
                break;
            case 'n':
                if(optarg) //Nalezen argument
                {
                    if(atoi(optarg)) n = atoi(optarg);
                    else {
                        printf("Převod čísla: \"%s\" selhal\n", optarg);
                        exit(2);
                    }
                }
                break;
            default:
                printf("Bad argument!\n");
                printf("Použití: ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
                return (0);
        }

    }
    if(ParamI) Print_Interfaces(); //Pokud nebyl zadán paramet I

    if (!(Protocols[0] || Protocols[1] || Protocols[2] || Protocols[3])) {
        for(int i = 0; i < 4; i++) Protocols[i] = 1;
    }

    for(int i = 0; i < 4; i++)
    {
        if(Protocols[i])
        {
            if((strcmp(filter_exp, "")) && Protocols[i]) //Prázdné
            {
                strcat(filter_exp, " or ");
            }
            if(i == 0)      strcat(filter_exp, "tcp");
            else if(i == 1) strcat(filter_exp, "udp");
            else if(i == 2) strcat(filter_exp, "arp");
            else if(i == 3) strcat(filter_exp, "icmp");
            if(Port && (i < 2))
            {
                char tmp [10];
                sprintf(tmp," port %d", Port);
                strcat(filter_exp, tmp);
            }

        }
    }
    //printf("\"%s\"\n", filter_exp);


    /* https://www.tcpdump.org/pcap.html
     * Autor 2010–2022 The Tcpdump Group
     *
     * */
    pcap_t *handle;			/* Session handle */
    //char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    //char filter_exp[] = "";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    /* Define the device */
    //dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    pcap_loop(handle, n, my_callback, NULL);

    /* And close the session */
    pcap_close(handle);

    exit(EXIT_SUCCESS);
}