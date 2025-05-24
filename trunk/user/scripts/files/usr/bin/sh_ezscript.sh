#!/bin/sh
# 连接 AP 的函数，扫描并连接到指定的 2.4G/5G AP

connAPSite() {
    # 加载配置文件
    [ -f /etc/storage/ap_script.sh ] || { logger -t "【连接 AP】" "错误：未找到 /etc/storage/ap_script.sh"; exit 1; }
    . /etc/storage/ap_script.sh

    # 验证依赖
    command -v iwpriv >/dev/null 2>&1 || { logger -t "【连接 AP】" "错误：未找到 iwpriv 命令"; exit 1; }
    command -v iwconfig >/dev/null 2>&1 || { logger -t "【连接 AP】" "错误：未找到 iwconfig 命令"; exit 1; }
    command -v nvram >/dev/null 2>&1 || { logger -t "【连接 AP】" "错误：未找到 nvram 命令"; exit 1; }

    logger -t "【连接 AP】" "10秒后开始扫描 AP"
    sleep 10

    # 获取配置
    ap_fenge=$(nvram get ap_fenge || echo '@')
    radio2_apcli=$(nvram get radio2_apcli || echo "apcli0")
    radio5_apcli=$(nvram get radio5_apcli || echo "apclii0")
    ap_rule=$(nvram get ap_rule || echo 0)
    ap_black=$(nvram get ap_black || echo 0)

    # 过滤有效 AP 配置
    AP_CONFIG="/tmp/ap2g5g.txt"
    AP_TEMP="/tmp/ap2g5g"
    grep -v '^#' "$AP_CONFIG" | grep -v "^$" > "$AP_TEMP"
    [ ! -s "$AP_TEMP" ] && { logger -t "【连接 AP】" "错误：无有效 AP 配置"; rm -f /tmp/apc.lock; exit 1; }

    # 检查锁文件，避免重复执行
    [ -f /tmp/apc.lock ] && { logger -t "【连接 AP】" "已有扫描进程运行，退出"; exit 0; }
    touch /tmp/apc.lock

    # 检查当前连接状态
    a2=$(iwconfig "$radio2_apcli" 2>/dev/null | awk -F'"' '/ESSID/ {print $2}')
    a5=$(iwconfig "$radio5_apcli" 2>/dev/null | awk -F'"' '/ESSID/ {print $2}')
    [ -z "$a2" ] && [ -z "$a5" ] && ap=1 || ap=0

    if [ "$ap" = "1" ] || [ "$1" = "scan" ]; then
        # 扫描 2.4G AP
        if grep -q "^2" "$AP_TEMP"; then
            radio_main=$(nvram get radio2_main || echo "ra0")
            logger -t "【连接 AP】" "扫描 2.4G AP ($radio_main)"
            iwpriv "$radio_main" set SiteSurvey=1
            sleep 2
            wds_aplist2g=$(iwpriv "$radio_main" get_site_survey)
            [ -z "$wds_aplist2g" ] && { sleep 3; wds_aplist2g=$(iwpriv "$radio_main" get_site_survey); }
        fi

        # 扫描 5G AP
        if grep -q "^5" "$AP_TEMP"; then
            radio_main=$(nvram get radio5_main || echo "rai0")
            logger -t "【连接 AP】" "扫描 5G AP ($radio_main)"
            iwpriv "$radio_main" set SiteSurvey=1
            sleep 2
            wds_aplist5g=$(iwpriv "$radio_main" get_site_survey)
            [ -z "$wds_aplist5g" ] && { sleep 3; wds_aplist5g=$(iwpriv "$radio_main" get_site_survey); }
        fi

        # 获取 AP 列表头部
        aplist_n=$(echo "$wds_aplist2g" | sed -n '2p')
        [ -z "$aplist_n" ] && aplist_n=$(echo "$wds_aplist5g" | sed -n '2p')

        # 处理 AP 配置
        while IFS= read -r line; do
            apc=$(echo "$line" | grep -v '^#' | grep -v "^$")
            [ -z "$apc" ] && continue

            radio=$(echo "$apc" | cut -d "$ap_fenge" -f1)
            rtwlt_mode_x=$(echo "$apc" | cut -d "$ap_fenge" -f2)
            rtwlt_sta_wisp=$(echo "$apc" | cut -d "$ap_fenge" -f3)
            rtwlt_sta_ssid=$(echo "$apc" | cut -d "$ap_fenge" -f4)
            rtwlt_sta_wpa_psk=$(echo "$apc" | cut -d "$ap_fenge" -f5)
            rtwlt_sta_bssid=$(echo "$apc" | cut -d "$ap_fenge" -f6 | tr '[:upper:]' '[:lower:]')

            # 根据频段选择扫描结果
            wds_aplist=$([ "$radio" = "2" ] && echo "$wds_aplist2g" || echo "$wds_aplist5g")
            radio_apcli=$([ "$radio" = "2" ] && echo "$radio2_apcli" || echo "$radio5_apcli")

            # 查找匹配的 AP
            site_survey=""
            if [ -n "$rtwlt_sta_ssid" ] && [ -n "$rtwlt_sta_bssid" ]; then
                site_survey=$(echo "$wds_aplist" | grep -Ei "[0-9]*[[:space:]]*$rtwlt_sta_ssid.*$rtwlt_sta_bssid" | sed -n '1p')
            elif [ -n "$rtwlt_sta_ssid" ]; then
                site_survey=$(echo "$wds_aplist" | grep -Ei "[0-9]*[[:space:]]*$rtwlt_sta_ssid.*" | sed -n '1p')
            elif [ -n "$rtwlt_sta_bssid" ]; then
                site_survey=$(echo "$wds_aplist" | grep -i "$rtwlt_sta_bssid" | sed -n '1p')
            fi

            # 如果 ap_rule=1，按信号强度排序
            if [ "$ap_rule" = "1" ]; then
                strongest_ap=""
                strongest_signal=0
                while IFS= read -r survey_line; do
                    signal=$(echo "$survey_line" | grep -o 'Signal([0-9]\+%)' | grep -o '[0-9]\+')
                    [ -n "$signal" ] && [ "$signal" -gt "$strongest_signal" ] && {
                        strongest_signal=$signal
                        strongest_ap=$survey_line
                    }
                done < <(echo "$wds_aplist" | grep -v '^#')
                [ -n "$strongest_ap" ] && site_survey="$strongest_ap"
            fi

            # 检查黑名单
            if [ "$ap_black" = "1" ] && [ -n "$rtwlt_sta_ssid" ]; then
                if grep -q "SSID:$rtwlt_sta_ssid" /tmp/apblack.txt || \
                   [ -n "$rtwlt_sta_bssid" ] && grep -q "BSSID:$rtwlt_sta_bssid" /tmp/apblack.txt; then
                    logger -t "【连接 AP】" "跳过黑名单 AP: $rtwlt_sta_ssid"
                    continue
                fi
            fi

            if [ -n "$site_survey" ]; then
                # 解析扫描结果
                ap_ch_ac=$(awk -v a="$aplist_n" -v b="Ch" 'BEGIN{print index(a,b)}')
                ap_ssid_ac=$(awk -v a="$aplist_n" -v b="SSID" 'BEGIN{print index(a,b)}')
                ap_bssid_ac=$(awk -v a="$aplist_n" -v b="BSSID" 'BEGIN{print index(a,b)}')
                ap_security_ac=$(awk -v a="$aplist_n" -v b="Security" 'BEGIN{print index(a,b)}')
                ap_signal_ac=$(awk -v a="$aplist_n" -v b="Signal" 'BEGIN{print index(a,b)}')
                ap_wmode_ac=$(awk -v a="$aplist_n" -v b="W-Mode" 'BEGIN{print index(a,b)}')

                Ch=$(echo "$site_survey" | awk -v s="$ap_ch_ac" '{print substr($0,s,3)}' | tr -d '[:space:]')
                SSID=$(echo "$site_survey" | awk -v s="$ap_ssid_ac" '{print substr($0,s,32)}' | tr -d '[:space:]')
                BSSID=$(echo "$site_survey" | awk -v s="$ap_bssid_ac" '{print substr($0,s,17)}' | tr '[:upper:]' '[:lower:]')
                Security=$(echo "$site_survey" | awk -v s="$ap_security_ac" '{print substr($0,s,20)}' | tr -d '[:space:]')
                Signal=$(echo "$site_survey" | awk -v s="$ap_signal_ac" '{print substr($0,s,10)}' | tr -d '[:space:]')
                WMode=$(echo "$site_survey" | awk -v s="$ap_wmode_ac" '{print substr($0,s,10)}' | tr -d '[:space:]')

                # 检查是否已连接
                ap=0
                if [ "$radio" = "2" ]; then
                    [ "$(iwconfig "$radio2_apcli" | grep -c "ESSID:.*$rtwlt_sta_ssid")" -gt 0 ] && ap=1
                    [ "$ap" = "0" ] && [ -n "$rtwlt_sta_bssid" ] && \
                        [ "$(iwconfig "$radio2_apcli" | grep -i "$rtwlt_sta_bssid" | wc -l)" -gt 0 ] && ap=1
                else
                    [ "$(iwconfig "$radio5_apcli" | grep -c "ESSID:.*$rtwlt_sta_ssid")" -gt 0 ] && ap=1
                    [ "$ap" = "0" ] && [ -n "$rtwlt_sta_bssid" ] && \
                        [ "$(iwconfig "$radio5_apcli" | grep -i "$rtwlt_sta_bssid" | wc -l)" -gt 0 ] && ap=1
                fi

                [ "$ap" = "1" ] && { logger -t "【连接 AP】" "已连接到 $rtwlt_sta_ssid"; rm -f /tmp/apc.lock; exit 0; }

                # 配置无线参数
                rtwlt_sta_auth_mode="open"
                rtwlt_sta_wpa_mode="0"
                rtwlt_sta_crypto=""
                case "$Security" in
                    *none*|*open*) rtwlt_sta_auth_mode="open"; rtwlt_sta_wpa_mode="0";;
                    *1psk*|*wpapsk*) rtwlt_sta_auth_mode="psk"; rtwlt_sta_wpa_mode="1";;
                    *2psk*) rtwlt_sta_auth_mode="psk"; rtwlt_sta_wpa_mode="2";;
                    *tkip*) rtwlt_sta_crypto="tkip";;
                    *aes*) rtwlt_sta_crypto="aes";;
                esac

                if [ "$radio" = "2" ]; then
                    nvram set rt_channel="$Ch"
                    iwpriv "$radio2_apcli" set Channel="$Ch"
                    nvram set rt_mode_x="$rtwlt_mode_x"
                    nvram set rt_sta_wisp="$rtwlt_sta_wisp"
                    nvram set rt_sta_ssid="$rtwlt_sta_ssid"
                    nvram set rt_sta_auth_mode="$rtwlt_sta_auth_mode"
                    nvram set rt_sta_wpa_mode="$rtwlt_sta_wpa_mode"
                    [ -n "$rtwlt_sta_crypto" ] && nvram set rt_sta_crypto="$rtwlt_sta_crypto"
                    nvram set rt_sta_wpa_psk="$rtwlt_sta_wpa_psk"
                    nvram set rt_HT_BW=0
                    nvram commit
                    command -v radio2_restart >/dev/null 2>&1 && radio2_restart || logger -t "【连接 AP】" "警告：radio2_restart 未定义"
                else
                    nvram set wl_channel="$Ch"
                    iwpriv "$radio5_apcli" set Channel="$Ch"
                    nvram set wl_mode_x="$rtwlt_mode_x"
                    nvram set wl_sta_wisp="$rtwlt_sta_wisp"
                    nvram set wl_sta_ssid="$rtwlt_sta_ssid"
                    nvram set wl_sta_auth_mode="$rtwlt_sta_auth_mode"
                    nvram set wl_sta_wpa_mode="$rtwlt_sta_wpa_mode"
                    [ -n "$rtwlt_sta_crypto" ] && nvram set wl_sta_crypto="$rtwlt_sta_crypto"
                    nvram set wl_sta_wpa_psk="$rtwlt_sta_wpa_psk"
                    nvram commit
                    command -v radio5_restart >/dev/null 2>&1 && radio5_restart || logger -t "【连接 AP】" "警告：radio5_restart 未定义"
                fi

                logger -t "【连接 AP】" "配置: Mode=$rtwlt_mode_x, WISP=$rtwlt_sta_wisp, SSID=$rtwlt_sta_ssid, Auth=$rtwlt_sta_auth_mode, WPA=$rtwlt_sta_wpa_mode, Crypto=$rtwlt_sta_crypto"
                logger -t "【连接 AP】" "AP信息: Ch=$Ch, SSID=$SSID, BSSID=$BSSID, Security=$Security, Signal=$Signal, WMode=$WMode"

                # 检查连接结果
                sleep 7
                if [ "$ap_black" = "1" ]; then
                    ping_text=$(ping -4 223.5.5.5 -c 1 -w 4 -q 2>/dev/null)
                    ping_loss=$(echo "$ping_text" | awk -F ', ' '{print $3}' | awk '{print $1}')
                    if [ -n "$ping_text" ] && [ "$ping_loss" != "100%" ]; then
                        logger -t "【连接 AP】" "成功连接 $rtwlt_sta_ssid 并联网"
                    else
                        logger -t "【连接 AP】" "连接 $rtwlt_sta_ssid 失败，加入黑名单"
                        echo "AP不联网列入黑名单:【Ch:$Ch】【SSID:$SSID】【BSSID:$BSSID】【Security:$Security】【Signal:$Signal】【WMode:$WMode】" >> /tmp/apblack.txt
                        continue
                    fi
                fi

                rm -f /tmp/apc.lock
                /etc/storage/ap_script.sh &
                exit 0
            fi
            [ "$ap_rule" = "1" ] && break
        done < "$AP_TEMP"
    fi
    rm -f /tmp/apc.lock
}

# 主脚本入口
case "$1" in
    connAPSite)
        connAPSite
        ;;
    connAPSite_scan)
        connAPSite "scan"
        ;;
    *)
        logger -t "【脚本】" "未知参数: $1"
        exit 1
        ;;
esac
