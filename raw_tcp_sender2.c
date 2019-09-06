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

#define CLI_PORT 20322
#define SVR_PORT 30232
#define MAX_DATA_SIZE 100

struct sockaddr_in source_socket_address, dest_socket_address;


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
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + payload_len);
	
	tcph->check = csum( (unsigned short*) pseudogram , psize) ;
	free(pseudogram);

}


static void fill_iphdr(struct tcphdr *tcph, struct iphdr *iph, char *datagram, uint16_t payload_len,char *src_ip, char *dst_ip){
		//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + payload_len;
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr (src_ip);	//Spoof the source ip address
	iph->daddr = inet_addr(dst_ip);

	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
}
/**/
static void init_syn_tcphdr(struct tcphdr *tcph ,struct iphdr *iph ,uint16_t payload_len ,int scr_port ,int dst_port ,char *pseudogram){
	//TCP Header
	tcph->source = htons (scr_port);
	tcph->dest = htons (dst_port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->doff = 5;	//tcp header size
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	calculate_tcp_checksum(tcph, iph, payload_len,pseudogram);
}

static void init_ack_tcphdr(struct tcphdr *tcph ,struct iphdr *iph ,uint16_t payload_len ,int scr_port ,int dst_port ,char *pseudogram){
	//TCP Header
	tcph->source = htons (scr_port);
	tcph->dest = htons (dst_port);
	tcph->seq =  htonl(ntohl(tcph->seq) + payload_len);
	tcph->ack_seq = htonl(1);
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


static void print_ip_info(struct iphdr *ip_packet ,struct tcphdr *tcph){

	memset(&source_socket_address, 0, sizeof(source_socket_address));
	source_socket_address.sin_addr.s_addr = ip_packet->saddr;
	memset(&dest_socket_address, 0, sizeof(dest_socket_address));
	dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

	printf("Incoming Packet: \n");
    printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
	printf("Source Address: %s\n", (char *)inet_ntoa(source_socket_address.sin_addr));
	printf("Destination Address: %s\n", (char *)inet_ntoa(dest_socket_address.sin_addr));
    printf("Identification: %d\n", ntohs(ip_packet->id));
    printf("SRC_PORT:%d DST_PORT:%d \n\n",ntohs(tcph->source),ntohs(tcph->dest));
}

int main(int argc, char** argv){
	if (argc != 3)
	{
		printf("./raw_tcp_sender [source ip] [dest ip]\n");
		exit(1);
	}

	int s_sock = socket(PF_INET,SOCK_RAW,IPPROTO_TCP);
	if(s_sock == -1)
	{
		printf("Create socket error!\n");
		exit(1);
	}

	/* init the data and iphdr, tcphdr address */
	char datagram[MAX_DATA_SIZE], *pseudogram, buffer[MAX_DATA_SIZE];
	memset (datagram, 0, MAX_DATA_SIZE);
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));

	/* init the tcp and ip */
	fill_iphdr(tcph ,iph ,datagram ,0 ,argv[1] ,argv[2] );
	init_syn_tcphdr(tcph ,iph ,0 ,CLI_PORT ,SVR_PORT ,pseudogram);

	/* IP_HDRINCL to tell the kernel that headers are included in the packet */
	int one = 1;
	const int *val = &one;
	if (setsockopt (s_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

	/* init Send Socket Addr */
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(SVR_PORT);
	sin.sin_addr.s_addr = inet_addr (argv[2]);

	struct sockaddr_in rin;
	memset(&rin, 0, sizeof(rin));
	rin.sin_family = AF_INET;
	rin.sin_addr.s_addr = inet_addr (argv[1]);
	rin.sin_port = htons(CLI_PORT);

	/*
	 *  you should bind the socket before "sendto" operation
	 *  otherwise it will be failed 
	 */
	int bind_len;    	
	bind_len = bind(s_sock ,(const struct sockaddr *)&rin , sizeof(rin));
	if (bind_len < 0) 
	{ 
		perror("bind failed"); 
		exit(0); 
	} 

	/* Send the syn packet */ 
	if (sendto (s_sock, datagram, iph->tot_len ,0 , (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("1.sendto failed");
	}
	else
	{
		printf ("1.Packet Send. Length : %d \n" , iph->tot_len);
	}


	/* set data message */
	static long *data;
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	static long sendnum = 12;
	memset(data ,0 ,sizeof(long));
	*data = sendnum;

	/* 
	 *	to receive the ACK && SYN packet
	 *  it hasn't been used;
	 */
	/* init receiver Socket Addr */

	/* receive */

	int recv_len = sizeof(struct sockaddr_in);
	int packet_size;
	packet_size = recvfrom(s_sock , buffer , MAX_DATA_SIZE , 0,(struct sockaddr *) &rin, &recv_len);
    if (packet_size == -1) 
    {
        // perror("Failed to get packets\n");
        // return 1;   
    }
    else
    {
    	/*
    	 * print packet info 
    	 */
        iph = buffer;
        tcph = buffer + sizeof(struct iphdr);
       	/* set data */
		data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);

		print_ip_info(iph ,tcph);

		/* switch saddr and addr*/
		__be32 tmp_addr;
		tmp_addr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp_addr;
		/*
		 * 	this is the magic code -0- 
		 *  without it it will send 40 byte ip without data...
		 */
		iph->tot_len = htons(sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(data));
		/* change the seq to seq_ack
		 * 
		 */
		tcph->seq =  htonl(ntohs(tcph->seq) -7);
		// tcph->ack_seq = htonl(-7);

		/*
		 * The last handshake and just send the packet
		 */
		while(1){
			*data = sendnum++;
			init_ack_tcphdr(tcph ,iph ,sizeof(data)  ,CLI_PORT ,SVR_PORT , pseudogram);

			if (sendto (s_sock, buffer, ntohs(iph->tot_len) ,0 , (struct sockaddr *) &sin, sizeof (sin)) < 0)
			{
				perror("2.sendto failed");
			}
			else
			{
				printf("tcph->seq:%d tcph->ack_seq:%d \n",ntohl(tcph->seq),ntohl(tcph->ack_seq));
				printf ("2.Packet Send. Length : %d \n" , iph->tot_len);
			}
			usleep(2500);
		}
	}
	close(s_sock);

}