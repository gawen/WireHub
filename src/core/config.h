#ifndef WIREHUB_CONFIG_H
#define WIREHUB_CONFIG_H

// source: https://www.wireguard.com/install/#kernel-requirements
#define WH_LINUX_MINVERSION { 3, 10 }

#define WH_ENV_CONFPATH "WH_CONFPATH"
#define WH_DEFAULT_CONFPATH "/etc/wirehub/"
#define WH_DEFAULT_SOCKPATH "/var/run/wirehub/"
#define WH_ENABLE_MINIUPNPC 1

#define WH_TUN_ICMP 1

#endif  // WIREHUB_CONFIG_H

