/* === PHICOMM K2P Wireless Router Board Definition === */

#define BOARD_PID               "K2P"
#define BOARD_NAME              "K2P"
#define BOARD_DESC              "PHICOMM K2P Wireless Router"
#define BOARD_VENDOR_NAME       "PHICOMM"
#define BOARD_VENDOR_URL        "http://www.phicomm.com/"
#define BOARD_MODEL_URL         "http://www.phicomm.com/"

#define BOARD_BOOT_TIME         30      /* seconds */
#define BOARD_FLASH_TIME        120     /* seconds */

/* === Wireless Capabilities === */
#define BOARD_HAS_5G_11AC       1
#define BOARD_NUM_ANT_5G_TX     2
#define BOARD_NUM_ANT_5G_RX     2
#define BOARD_NUM_ANT_2G_TX     2
#define BOARD_NUM_ANT_2G_RX     2

/* === Ethernet & PHY === */
#define BOARD_HAS_EPHY_L1000    1       /* LAN supports 1000 Mbps */
#define BOARD_HAS_EPHY_W1000    1       /* WAN supports 1000 Mbps */
#define BOARD_NUM_ETH_LEDS      0

/* === USB Configuration === */
#define BOARD_NUM_UPHY_USB3     0       /* No USB 3.0 ports */
#define BOARD_USB_PORT_SWAP     0       /* USB port order not swapped */
