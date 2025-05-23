##################################################################
# Board PID # Board Name       # PRODUCT        # Note
##################################################################
# G-AX1800  # G-AX1800         # MT7621, MT7915 # Wi-Fi 6, DBDC
##################################################################

# Compiler flags
CFLAGS += -DBOARD_G_AX1800          # Board identifier
CFLAGS += -DBOARD_MT7915_DBDC       # MT7915 Wi-Fi chip with Dual Band Dual Concurrent
CFLAGS += -DBOARD_HAS_DBDC          # Dual-Band Dual-Concurrent Support

# Hardware configuration
BOARD_NUM_USB_PORTS   := 0           # Number of USB ports (0 = none) 
CONFIG_BOARD_RAM_SIZE := 256         # RAM size in MB
