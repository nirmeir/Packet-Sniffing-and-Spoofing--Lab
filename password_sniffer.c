#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h> //contain the ethernet header
#include <netinet/ip.h>	//contain the ip header
#include <netinet/tcp.h> // contain the tcp header
#include <linux/if_ether.h>

struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};


#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
u_char  ip_vhl;                 /* version << 4 | header length >> 2 */

};

#define SIZE_ETHERNET 14


/*This function will be invoked by pcap for each captured packet.We can process each packet inside the function.*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip; // build a iphdr struct to get access to the ip addresses.
    struct tcphdr *tcp;
    struct sockaddr_in address; // will contain the source+dest addr
    char *payload; // eth(ip(tcp(payload)))
    unsigned int payload_len = header->len - (sizeof(struct iphdr) + sizeof (struct tcphdr));
    ip = (struct iphdr *) (packet + SIZE_ETHERNET); // modify ip
    memset(&address, 0, sizeof(address));
    tcp = (struct tcphdr*) (packet + SIZE_ETHERNET+ sizeof(struct iphdr)); // modify ip

    payload = (char*)(packet+ SIZE_ETHERNET+ sizeof(struct iphdr) + sizeof (struct tcphdr)+12);



    address.sin_addr.s_addr = ip->saddr;// modify source

    printf("Got a packet\n");
    char *src = inet_ntoa(address.sin_addr);// converting source to fine ip address
    printf("src ip: %s\n", src);
    address.sin_addr.s_addr = ip->daddr;// modify dest
    char *dst = inet_ntoa(address.sin_addr);// converting dest to fine ip address
    printf("dst ip: %s\n", dst);
    if(payload_len){
        printf("payload : \n");
        for (int i = 0; i < payload_len; ++i) {

            if(isprint(payload[i]))
                printf("%c",payload[i]);
            else{
                break;
            }
        }
        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp && dst port 23";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name br-3bef0344ba07
    handle = pcap_open_live("br-51a6dc77b85b", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    //Close the handle
    return 0;
}
