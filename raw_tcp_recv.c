#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<arpa/inet.h>
#include<unistd.h>
#include<linux/in.h>
#include <linux/types.h>

#define CLI_PORT 20321
#define SVR_PORT 30231
#define MAX_DATA_SIZE 100
/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if(nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

static void calculate_tcp_checksum(struct tcphdr *tcph, struct iphdr *iph, uint16_t payload_len,char *pseudogram){
	struct pseudo_header psh;
	//Now the TCP checksum
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) +  payload_len);
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);
	free(pseudogram);
}

static void print_ip_info(struct iphdr *ip_packet){
	printf("Incoming Packet: \n");
    printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
    // printf("Source Address: %p \n",  &ip_packet->saddr);
    // printf("Destination Address: %p\n", &ip_packet->daddr);
    printf("Identification: %d\n", ntohs(ip_packet->id));
}

static void init_syn_ack_tcphdr(struct tcphdr *tcph ,struct iphdr *iph ,uint16_t payload_len ,__be16 src_port ,__be16 dst_port ,char *pseudogram){
	//TCP Header
	tcph->source = src_port;
	tcph->dest = dst_port;
    tcph->ack_seq = htonl(ntohs(tcph->seq) + 1);
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=1;
	tcph->urg=0;
	tcph->doff = 6;	//tcp header size,syn !=0 doff = 6
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;
	
	calculate_tcp_checksum(tcph, iph, payload_len,pseudogram);
}

static void init_ack_tcphdr(struct tcphdr *tcph ,struct iphdr *iph ,uint16_t payload_len ,__be16 src_port ,__be16 dst_port ,char *pseudogram){
	//TCP Header
	tcph->source = src_port;
	tcph->dest = dst_port;
	tcph->ack_seq = htonl(ntohl(tcph->seq) + payload_len);
	tcph->seq =  htonl(1);
	tcph->fin=0;
	tcph->syn=0;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=1;
	tcph->urg=0;
	tcph->doff = 5;	//tcp header size
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	calculate_tcp_checksum(tcph, iph, payload_len,pseudogram);
}

int main(int argc, char** argv){
	if (argc != 2)
	{
		printf("./raw_tcp_recv [server ip] \n");
		exit(1);
	}

	int c_sock = socket(PF_INET,SOCK_RAW,IPPROTO_TCP);
	if(c_sock == -1)
	{
		printf("Create socket error!\n");
		exit(1);
	}

	/* init the data and iphdr, tcphdr address */
	char buffer[MAX_DATA_SIZE], *pseudogram;
	memset (buffer, 0, MAX_DATA_SIZE);

	/*
	*  bind the socket to receievr ip and receiver port 
	*  If not, we wil receive all of packet sending to computer.
	*/
	struct sockaddr_in servaddr;  
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family  = AF_INET; // IPv4 
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);
	servaddr.sin_port = htons(SVR_PORT); 

	static int bind_len;
	if ( bind(c_sock, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) 
	{ 
		perror("bind failed"); 
		exit(0); 
    } 

	/* IP_HDRINCL to tell the kernel that headers are included in the packet */
	int one = 1;
	const int *val = &one;
	if (setsockopt (c_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
		perror("Error setting IP_HDRINCL");
		exit(0);
    }
	struct sockaddr_in cliaddr; //here is magic code -0-  
	int clilen;
	int packet_size;

Receive_SYN:
	packet_size = recvfrom(c_sock , buffer , MAX_DATA_SIZE , 0, (struct sockaddr *) &cliaddr, &clilen);
	if (packet_size == -1) 
    {
		perror("Failed to get packets\n");
		// return 1;   
	}

	else
	{
		/*
		 *  send the 2th a SYN && ACK packet back to 
		 *  the data in buffer is all of message in  
		 */
		/* init the iph and tcph */
        struct iphdr *iph = (struct iphdr *)buffer;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
		/* set data */
		static long *data;
		data = buffer + sizeof(iph) + sizeof(tcph);
		if(ntohs(tcph->dest) != SVR_PORT){

			goto Receive_SYN;
		}

		/* switch the ip addr */
		__be32 tmp_addr;
		tmp_addr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp_addr;
		/* switch the port */
		/* set the ACK && SYN pakcet */
		init_syn_ack_tcphdr(tcph, iph, 4 ,tcph->dest,tcph->source,pseudogram);
		if (sendto (c_sock, buffer, ntohs(iph->tot_len), 0,(struct sockaddr *) &cliaddr,  clilen) < 0)
		{
			perror("sendto failed");
		}
		else
		{
			printf("Send the ACK & SYN Packet,SRC_PORT:%d DST_PORT:%d \n",ntohs(tcph->source),ntohs(tcph->dest));
			/* received the data */
			int count = 0;
			while(1)
			{

			Receive_ACK:
				packet_size = recvfrom(c_sock , buffer , MAX_DATA_SIZE , 0, (struct sockaddr *) &cliaddr, &clilen);
			    if (packet_size == -1) 
				{
					perror("2.Failed to get packets\n");
					// return 1; 
				}
				iph = buffer;
				tcph = buffer + sizeof(struct iphdr);
				data = buffer + sizeof(iph) + sizeof(tcph);
				// *data = 0;
				iph->tot_len = htons(ntohs(iph->tot_len) - 8);/*试试能不能把回的这个数据干掉 还真可以*/
				if(ntohs(tcph->dest) != SVR_PORT)
				{
					goto Receive_ACK;
				}

				/* switch the ip addr */
				__be32 tmp_addr;
				tmp_addr = iph->saddr;
				iph->saddr = iph->daddr;
				iph->daddr = tmp_addr;
				init_ack_tcphdr(tcph, iph,  0, tcph->dest, tcph->source,pseudogram);
				if (sendto (c_sock, buffer, ntohs(iph->tot_len), 0,(struct sockaddr *) &cliaddr,  clilen) < 0)
				{
					perror("sendto failed");
				}
				else
				{
					++count;
					if(count %100 == 0){
						printf("receive the %d packet and send back\n", count);
					}
				}
	    	}


        }

	}
	close(c_sock);

}