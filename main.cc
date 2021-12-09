#include "deauth.h"

bool chk = true;

int main(int argc,char* argv[])
{
    if(argc!=3 && argc!=4)
    {
        printf("argc : %d\n",argc);
        usage();
        return -1;
    }

    Mac ap,station;

    ap = Mac(argv[2]);
    if(argc == 4) station = Mac(argv[3]);
    else station = Mac::broadcastMac();

    return deauth(argv[1],ap,station);
}