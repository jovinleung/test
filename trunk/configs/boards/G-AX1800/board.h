/* === G-AX1800 Wireless Router Board Definition === */

#define BOARD_PID               "G-AX1800"
#define BOARD_NAME              "G-AX1800"
#define BOARD_DESC              "G-AX1800 Wireless Router"
#define BOARD_VENDOR_NAME       "FCJ GROUP"
#define BOARD_VENDOR_URL        "http://www.fcjjt.com/"
#define BOARD_MODEL_URL         "http://www.fcjjt.com/"

#define BOARD_BOOT_TIME         20      /* Boot time in seconds */
#define BOARD_FLASH_TIME        120     /* Flash write time in seconds */

/* === Wireless Capabilities === */
#define BOARD_HAS_5G_11AC       1       /* Supports 5GHz 802.11ac */
#define BOARD_HAS_5G_11AX       1       /* Supports 5GHz 802.11ax (Wi-Fi 6) */
#define BOARD_HAS_2G_11AX       1       /* Supports 2.4GHz 802.11ax (Wi-Fi 6) */
#define BOARD_HAS_DBDC          1       /* Dual-Band Dual-Concurrent Support */
#define BOARD_NUM_ANT_5G_TX     2
#define BOARD_NUM_ANT_5G_RX     2
#define BOARD_NUM_ANT_2G_TX     2
#define BOARD_NUM_ANT_2G_RX     2

/* === Ethernet Configuration === */
#define BOARD_NUM_ETH_EPHY      4       /* 4 Ethernet PHY ports (LAN/WAN total) */
#define BOARD_HAS_EPHY_L1000    1       /* LAN supports 1000 Mbps */
#define BOARD_HAS_EPHY_W1000    1       /* WAN supports 1000 Mbps */
#define BOARD_NUM_ETH_LEDS      0       /* No independent Ethernet LED indicators */
