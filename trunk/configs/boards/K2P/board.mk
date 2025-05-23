#####################################################################
#  Board PID  |  Board Name     |  PRODUCT   |       Note
#####################################################################
#   K2P       |  K2P            |  MT7621    |  PHICOMM K2P with MT7615 DBDC
#####################################################################

# Compiler flags
CFLAGS += -DBOARD_K2P 
CFLAGS += -DBOARD_MT7615_DBDC

# Hardware configuration
BOARD_NUM_USB_PORTS   := 0           # USB port configuration
CONFIG_BOARD_RAM_SIZE := 128         # RAM size in MB
