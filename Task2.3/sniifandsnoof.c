#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

struct icmpheader
{
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};
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
#define IP_HL(ip) (((ip)->iph_ihl) & 0x0f) // 1111 0101 1011 0010 AND 0000 1111 = 0000
#define IP_V(ip) (((ip)->iph_ver) >> 4)
#define packet_size 512

unsigned short checksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

void send_spoof_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_addr;
    const int on = 1;
    // Step 1: Create a raw network socket.
    int sock = 0;
    if ((sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() eroor");
    }
    // Step 2: Set socket option.
    int se = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    // Step 3: Provide needed information about destination.
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    printf("    from :  %s\n", inet_ntoa(ip->iph_sourceip));
    printf("    to : %s\n", inet_ntoa(ip->iph_destip));
    close(sock);
    return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) // check if its type IP
    {
        // copy the data to an ip header, the buffer includes all the data we need
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        // check the protocol
        if (ip->iph_protocol == 1)
        {
            int size_ip = IP_HL(ip) * 4;
            struct icmpheader *new_icmp = (struct icmpheader *)(packet + size_ip + sizeof(struct ethheader));
            
            if (new_icmp->icmp_type == 8)
            {
                // Construct IP: swap src and dest in faked ICMP packet
                struct in_addr source = ip->iph_sourceip;
                ip->iph_sourceip = ip->iph_destip;
                ip->iph_destip = source;
                ip->iph_ttl = 64;

                // Fill in all the needed ICMP header information.
                // ICMP Type: 8 is request, 0 is reply.
                new_icmp->icmp_type = 0;
                new_icmp->icmp_chksum = 0;

                int datasize = ntohs(ip->iph_len) - sizeof(struct ipheader)- sizeof(struct icmpheader);
                new_icmp->icmp_chksum = checksum((unsigned short *)new_icmp, sizeof(struct icmpheader) + datasize);
                send_spoof_packet(ip);
                
            }
        }
    }
    
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] = icmp-echo";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // can be change to lo so the myping.c file will worke

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    return 0;
}