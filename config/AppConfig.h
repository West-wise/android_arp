//
// Created by psh0036 on 26. 1. 28..
//

#ifndef ANDROID_ARP_APPCONFI_H
#define ANDROID_ARP_APPCONFI_H

namespace AppConfig {
    namespace Arp {
        constexpr int MAX_RETRY = 3;
        constexpr int RESOLVE_TIMEOUT = 1000;
    }
    namespace System {
        constexpr int PCAP_READ_TMOUT_MS = 1;
    }
}



#endif //ANDROID_ARP_APPCONFI_H