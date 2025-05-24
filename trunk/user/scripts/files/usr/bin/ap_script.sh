#!/bin/sh
# /etc/storage/ap_script.sh
# 监控并管理 AP 中继连接，每 15 秒检查一次。

# 配置参数
nvram set ap_check=0           # 0: 互联网断线后自动搜索；1: AP 断开时自动搜索
nvram set ap_inet_check=0      # 0: 连接 AP 即成功；1: 需连接 AP 和互联网
nvram set ap_time_check=0      # 0: 连接后停止搜索；>=10: 每 N 秒搜索
nvram set ap_black=0           # 0: 禁用黑名单；1: 启用黑名单
nvram set ap_fenge='@'         # AP 配置分隔符
nvram set ap_rule=0            # 0: 优先连接第一行 AP；1: 连接最强信号

# 验证依赖
command -v nvram >/dev/null 2>&1 || { logger -t "AP 中继" "错误：未找到 nvram 命令"; exit 1; }
command -v iwconfig >/dev/null 2>&1 || { logger -t "AP 中继" "错误：未找到 iwconfig 命令"; exit 1; }
command -v ifconfig >/dev/null 2>&1 || { logger -t "AP 中继" "错误：未找到 ifconfig 命令"; exit 1; }

# 创建 AP 配置文件
AP_CONFIG="/tmp/ap2g5g.txt"
AP_TEMP="/tmp/ap2g5g"
cat >"$AP_CONFIG" <<-\EOF
# AP 配置格式：band@mode@role@SSID@password[@MAC]
# band: 2=2.4Ghz, 5=5Ghz
# mode: 3=AP-Client, 4=AP-Client+AP
# role: 0=LAN 桥接, 1=WAN (无线 ISP)
# 示例：
#2@4@1@ASUS@1234567890
#2@4@1@ASUS_中文@1234567890@34:bd:f9:1f:d2:b1
EOF

# 检查路由器模式
rt_mode_x=$(nvram get rt_mode_x)
wl_mode_x=$(nvram get wl_mode_x)
if [ "$rt_mode_x" -le 2 ] && [ "$wl_mode_x" -le 2 ]; then
    logger -t "AP 中继" "无效的路由器模式，退出"
    exit 0
fi

# 过滤非空、非注释行
grep -v '^#' "$AP_CONFIG" | grep -v "^$" > "$AP_TEMP"
[ ! -s "$AP_TEMP" ] && { logger -t "AP 中继" "未找到有效的 AP 配置"; exit 0; }

# 停止已运行的 sh_apauto.sh
killall sh_apauto.sh 2>/dev/null

# 创建并运行自动连接脚本
cat >"/tmp/sh_apauto.sh" <<-\EOF
#!/bin/sh
[ "$1" = "crontabs" ] && sleep 15
logger -t "AP 中继" "启动连接监控"

while [ -s "$AP_TEMP" ]; do
    # 检查冲突进程
    if ! ps | grep -qE "[a]p_script.sh|[s]h_ezscript.sh"; then
        rm -f /tmp/apc.lock
    fi

    # 获取无线接口
    radio2_apcli=$(nvram get radio2_apcli || echo "apcli0")
    radio5_apcli=$(nvram get radio5_apcli || echo "apclii0")

    ap_check=$(nvram get ap_check)
    if [ "$ap_check" = "1" ] && [ ! -f /tmp/apc.lock ]; then
        # 检查 AP 是否断开
        a2=$(ifconfig 2>/dev/null | grep "$radio2_apcli")
        a5=$(ifconfig 2>/dev/null | grep "$radio5_apcli")
        if [ -z "$a2" ] && [ -z "$a5" ]; then
            logger -t "AP 中继" "AP 断开，启动扫描"
            if ! ps | grep -q "[s]h_ezscript.sh"; then
                /etc/storage/sh_ezscript.sh connAPSite_scan &
            fi
            sleep 10
        fi
    fi

    ap_time_check=$(nvram get ap_time_check)
    if [ "$ap_time_check" -ge 9 ] && [ ! -f /tmp/apc.lock ]; then
        ap_fenge=$(nvram get ap_fenge)
        # 获取优先 AP 配置
        first_ap=$(grep -v '^#' "$AP_TEMP" | head -1)
        rtwlt_sta_ssid_1=$(echo "$first_ap" | cut -d "$ap_fenge" -f4)
        rtwlt_sta_bssid_1=$(echo "$first_ap" | cut -d "$ap_fenge" -f6 | tr '[:upper:]' '[:lower:]')
        [ "$(echo "$first_ap" | cut -d "$ap_fenge" -f1)" = "5" ] && radio2_apcli="$radio5_apcli"

        # 获取当前连接信息
        rtwlt_sta_ssid=$(iwconfig "$radio2_apcli" 2>/dev/null | awk -F'"' '/ESSID/ {print $2}')
        rtwlt_sta_bssid=$(iwconfig "$radio2_apcli" 2>/dev/null | grep -o 'Access Point: [0-9A-Fa-f:]\+' | cut -d' ' -f3 | tr '[:upper:]' '[:lower:]')

        # 检查是否连接到优先 AP
        if [ -n "$rtwlt_sta_ssid_1" ] && [ -n "$rtwlt_sta_ssid" ] && [ "$rtwlt_sta_ssid_1" = "$rtwlt_sta_ssid" ] && \
           { [ -z "$rtwlt_sta_bssid_1" ] || [ "$rtwlt_sta_bssid_1" = "$rtwlt_sta_bssid" ]; }; then
            ap_time_check=0
        fi

        if [ "$ap_time_check" -ge 9 ]; then
            logger -t "AP 中继" "$ap_time_check 秒后扫描优先 AP $rtwlt_sta_ssid_1"
            sleep "$ap_time_check"
            if ! ps | grep -q "[s]h_ezscript.sh"; then
                /etc/storage/sh_ezscript.sh connAPSite_scan &
            fi
            sleep 10
        fi
    fi

    if [ "$ap_check" = "0" ] && [ ! -f /tmp/apc.lock ]; then
        # 检查互联网连接
        ping_text=$(ping -4 223.5.5.5 -c 1 -w 4 -q 2>/dev/null)
        ping_loss=$(echo "$ping_text" | awk -F ', ' '{print $3}' | awk '{print $1}')
        if [ -z "$ping_text" ] || [ "$ping_loss" = "100%" ]; then
            logger -t "AP 中继" "互联网断开，启动扫描"
            if ! ps | grep -q "[s]h_ezscript.sh"; then
                /etc/storage/sh_ezscript.sh connAPSite_scan &
            fi
            sleep 10
        fi
    fi

    sleep 15
done
EOF

chmod 755 "/tmp/sh_apauto.sh"
if ! ps -w | grep -q "[s]h_apauto.sh"; then
    /tmp/sh_apauto.sh "$1" &
fi
