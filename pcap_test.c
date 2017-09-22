#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

char *dev;

void callback(u_char *param, const  struct pcap_pkthdr *pkth, const  u_char *packet){

    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;

    struct ip *ip;
    const char *data;

    ethh = (struct ethhdr *)packet;

    if(ntohs(ethh->h_proto) == ETHERTYPE_IP){  //if ip packet is captured
        iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
        ip = (struct ip *)(packet + sizeof(struct ethhdr));
        if(ip->ip_p == IPPROTO_TCP){ //if tcp packet is captured
            tcph = (struct tcphdr*)(packet + (ip->ip_hl)*4 + sizeof(struct ethhdr));
            printf("DEV: %s", dev);

            printf("\nSource MAC Adrress: ");
            for(int i = 0; i < 6; i++) printf("%02x", ethh->h_source[i]);

            printf("\nDest MAC Address: ");
            for(int i = 0; i < 6; i++) printf("%02x", ethh->h_dest[i]);
          
            printf("\nSource IP: %s", inet_ntoa(*(struct in_addr *)&iph->saddr));
            printf("\nDest   IP: %s", inet_ntoa(*(struct in_addr *)&iph->daddr));
            printf("\nSource Port: %u", ntohs(tcph->source));
            printf("\nSource Port: %u\n", ntohs(tcph->dest));

            data = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct tcphdr) + sizeof(struct iphdr));
            if(data == NULL){
                printf("No Data\n");
            }else{
                printf("Data:\n%s\n", data);
            }

        }else{ 
            printf("DEV: %s\n", dev);
            
            printf("\nSource MAC Address: ");
            for(int i = 0; i < 6; i++) printf("%02x", ethh->h_source[i]);
            
            printf("\nDest MAC Address: ");
            for(int i = 0; i < 6; i++) printf("%02x", ethh->h_dest[i]);

            printf("\nSource IP: %s", inet_ntoa(*(struct in_addr *)&iph->saddr));
            printf("\nDest   IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

        }
    }else{
        printf("DEV: %s", dev);
        
        printf("\nSource MAC Address: ");
        for(int i = 0; i < 6; i++) printf("%02x", ethh->h_source[i]);

        printf("\nDest MAC Address: ");
        for(int i = 0; i < 6; i++) printf("%02x", ethh->h_dest[i]);
    }

}

        
int main(int argc, char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    const char* name = "Kim subong" ;
    printf("[sub26_2017]pcap_test[%s]", name);

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }

    handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(handler, 0, callback, NULL);

    return 0;
}

