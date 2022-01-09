#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>

struct ethheader
{
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* IP? ARP? RARP? etc */
};
struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length in byte
        iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};
#define IP_HL(ip) (((ip)->iph_ihl) & 0x0f) //
#define IP_V(ip) (((ip)->iph_ver) >> 4)
/* TCP header */
typedef unsigned int tcp_seq;

struct sniff_tcp
{
    unsigned short th_sport; /* source port */
    unsigned short th_dport; /* destination port */
    tcp_seq th_seq;          /* sequence number */
    tcp_seq th_ack;          /* acknowledgement number */
    unsigned char th_offx2;  /* data offset, rsvd */
    unsigned char th_flags;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    unsigned short th_win; /* window */
    unsigned short th_sum; /* checksum */
    unsigned short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int data_len = 0;
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) // check if its type IP
  {
    // copy the data to an ip header, the buffer includes all the data we need
    struct ipheader *ipHeader = (struct ipheader *)(packet + sizeof(struct ethheader));
    int size = IP_HL(ipHeader) * 4;

    // check if the protocol is TCP, TCP protocol number is 6
    if (ipHeader->iph_protocol == IPPROTO_TCP)
    {
      struct sniff_tcp *tcpHeader = (struct sniff_tcp *)(packet + size + sizeof(struct ethheader));
      int len = TH_OFF(tcpHeader) * 4;
      char *data = (u_char *)(packet + size + sizeof(struct ethheader) + len);
      data_len = ntohs(ipHeader->iph_len) - (size + len);
      if (data_len > 0)
      {
        printf("Got a packet\n");
        printf("Source IP        :   %s\n", inet_ntoa(ipHeader->iph_sourceip));
        printf("Destination IP   :   %s\n", inet_ntoa(ipHeader->iph_destip));
        printf("data = ");
        for (int i = 0; i < data_len; i++)
        {
          if (isprint(*data))
          {
            printf("%c", *data);
          }
          data++;
        }
        printf("\n");
      }
    }
  }
}
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto TCP";
  bpf_u_int32 net;
  //Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  //Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);
  //Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle); //Close the handle
  return 0;
}
