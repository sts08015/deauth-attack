#pragma once
#include <cstdint>
#include "mac.h"

#define BEACON 8

#pragma pack(push,1)
typedef struct radiotap_header
{
    uint8_t     revision;
    uint8_t     pad;
    uint16_t    hdr_len;
    uint32_t    present_flg;
}RTHDR;
#pragma pack(pop)
typedef RTHDR* PRTHDR;

#pragma pack(push,1)
typedef struct beacon_frame
{
    uint8_t     version:2;
    uint8_t     type:2;
    uint8_t     subtype:4;
    uint8_t     flags;
    uint16_t    duration;
    Mac         dst;
    Mac         src;
    Mac         bssid;
    uint16_t    frag_seq;
}BF;
#pragma pack(pop)
typedef BF* PBF;

#pragma pack(push,1)
typedef struct fixed_manage_frame
{
    uint64_t timestamp;
    uint16_t beacon_intv;
    uint16_t cap;
}FMF;
#pragma pack(pop)
typedef FMF* PFMF;


#pragma pack(push,1)
typedef struct deauth_frame
{
    RTHDR       radiotap;
    uint8_t     zero_pad[3];
    BF          deauth;
    uint16_t    reason;
}DF;
#pragma pack(pop)
typedef DF* PDF;