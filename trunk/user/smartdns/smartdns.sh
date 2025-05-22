#!/bin/sh
# Copyright (C) 2018 Nick Peng (pymumu@gmail.com)
# Copyright (C) 2019 chongshengB (bkye@vip.qq.com)
# Copyright (C) 2022 TurBoTse (860018505@qq.com)
# Optimized SmartDNS management script with fixed variable names

# 配置路径
storage_Path="/etc/storage"
smartdns_Bin="/usr/bin/smartdns"
smartdns_Ini="$storage_Path/smartdns_conf.ini"
scripts_smartdns_conf="$storage_Path/smartdns.conf"
scripts_smartdns_tmp_conf=$(mktemp /tmp/smartdns_tmp.XXXXXX)
scripts_smartdns_address_conf="$storage_Path/smartdns_address.conf"
scripts_smartdns_blacklist_ip_conf="$storage_Path/smartdns_blacklist-ip.conf"
scripts_smartdns_whitelist_ip_conf="$storage_Path/smartdns_whitelist-ip.conf"
scripts_smartdns_custom_conf="$storage_Path/smartdns_custom.conf"
dnsmasq_Conf="$storage_Path/dnsmasq/dnsmasq.conf"
chn_Route="$storage_Path/chinadns/chnroute.txt"

# 清理临时文件
trap 'rm -f "$scripts_smartdns_tmp_conf" /tmp/whitelist.conf /tmp/blacklist.conf /tmp/sdnsipset.conf /tmp/anti-ad-for-smartdns.conf' EXIT

# 日志函数
log_debug() { [ "$DEBUG" = "1" ] && logger -t "SmartDNS" "DEBUG: $1"; }
log_error() { logger -t "SmartDNS" "ERROR: $1"; exit 1; }
log_info() { logger -t "SmartDNS" "$1"; }

# 验证变量
check_variable() {
    local var_name=$1 var_value=$2
    if [ -z "$var_value" ]; then
        log_error "$var_name 未设置或为空"
    fi
}

# 验证端口
sanitize_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_error "无效端口: $port"
    fi
    echo "$port"
}

# 验证 IP 地址
check_ip_addr() {
    local ip=$1
    if echo "$ip" | grep -qE "^[0-9]{1,3}\.([0-9]{1,3}\.){2}[0-9]{1,3}$"; then
        local a b c d
        a=$(echo "$ip" | awk -F. '{print $1}')
        b=$(echo "$ip" | awk -F. '{print $2}')
        c=$(echo "$ip" | awk -F. '{print $3}')
        d=$(echo "$ip" | awk -F. '{print $4}')
        for num in $a $b $c $d; do
            if [ "$num" -gt 255 ] || [ "$num" -lt 0 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# 获取 IP 地址
get_ips() {
    IPS4=$(ifconfig br0 | grep -oP 'inet addr:\K[\d.]+' | grep -v '^127\.' | head -n1)
    [ -z "$IPS4" ] && log_error "无法获取 br0 的 IPv4 地址"
    if ip -6 addr show br0 >/dev/null 2>&1; then
        IPS6=$(ip -6 addr show br0 | grep -m1 'inet6.*global' | awk '{print $2}' | cut -d'/' -f1)
    else
        IPS6=""
        log_debug "br0 上未启用 IPv6"
    fi
}

# 读取配置
read_ini() {
    if [ -r "$smartdns_Ini" ]; then
        hosts_type=$(sed -n '1p' "$smartdns_Ini")
        sdns_redirected=$(sed -n '2p' "$smartdns_Ini")
        sdns_ported=$(sed -n '3p' "$smartdns_Ini")
        sdnse_ported=$(sed -n '4p' "$smartdns_Ini")
    else
        hosts_type=0
        sdns_redirected=0
        sdns_ported="$sdns_port"
        sdnse_ported="$sdnse_port"
    fi
}

# 检查文件 MD5
check_md5() {
    log_debug "进入 Check_md5"
    local files="$storage_Path/smartdns_*.sh"
    local md5="$storage_Path/smartdns.md5"
    local new_md5=$(mktemp /tmp/smartdns_md5.XXXXXX)
    trap 'rm -f "$new_md5"' EXIT
    if ! ls $files >/dev/null 2>&1; then
        log_error "未找到 smartdns 脚本文件"
    fi
    md5sum $files > "$new_md5" || log_error "无法生成 MD5 文件"
    if [ -s "$md5" ]; then
        if ! diff "$md5" "$new_md5" >/dev/null 2>&1; then
            cp "$new_md5" "$md5" && mtd_storage.sh save >/dev/null 2>&1 || log_error "无法保存 MD5 文件"
        fi
    else
        cp "$new_md5" "$md5" && mtd_storage.sh save >/dev/null 2>&1 || log_error "无法创建 MD5 文件"
    fi
    log_debug "离开 Check_md5"
}

# 检查 Shadowsocks 配置
check_ss() {
    if [ -s /etc_ro/ss_ip.sh ] && [ "$(nvram get ss_enable)" = "1" ] && \
       [ "$(nvram get ss_run_mode)" = "router" ] && [ "$(nvram get pdnsd_enable)" = "0" ]; then
        log_error "检测到 SS 绕过大陆模式且启用了 pdnsd，请调整为 SmartDNS + 手动配置模式"
    fi
}

# 生成 SmartDNS 配置
get_sdns_conf() {
    :>"$scripts_smartdns_tmp_conf"
    cat << EOF >> "$scripts_smartdns_tmp_conf"
server-name $sdns_name
cache-size $sdns_cache
rr-ttl $sdns_rr_ttl
rr-ttl-min $sdns_rr_ttl_min
rr-ttl-max $sdns_rr_ttl_max
tcp-idle-time $sdns_tcp_idle_time
rr-ttl-reply-max $sdns_rr_ttl_reply_max
max-reply-ip-num $sdns_max_reply_ip_num
serve-expired-ttl $sdns_exp_ttl
serve-expired-reply-ttl $sdns_exp_ttl_max
serve-expired-prefetch-time $sdns_exp_prefetch_time
force-qtype-SOA $sdns_force_qtype_soa
speed-check-mode $sdns_speed_mode
log-level error
EOF

    ARGS_1=""
    [ "$sdns_address" = "1" ] && ARGS_1="$ARGS_1 -no-rule-addr"
    [ "$sdns_ns" = "1" ] && ARGS_1="$ARGS_1 -no-rule-nameserver"
    [ "$sdns_ipset" = "1" ] && ARGS_1="$ARGS_1 -no-rule-ipset"
    [ "$sdns_speed" = "1" ] && ARGS_1="$ARGS_1 -no-speed-check"
    [ "$sdns_as" = "1" ] && ARGS_1="$ARGS_1 -no-rule-soa"
    if [ "$sdns_ipv6_server" = "1" ]; then
        echo "bind [::]:$sdns_port $ARGS_1" >> "$scripts_smartdns_tmp_conf"
        [ "$sdns_tcp_server" = "1" ] && echo "bind-tcp [::]:$sdns_port $ARGS_1" >> "$scripts_smartdns_tmp_conf"
    else
        echo "bind :$sdns_port $ARGS_1" >> "$scripts_smartdns_tmp_conf"
        [ "$sdns_tcp_server" = "1" ] && echo "bind-tcp :$sdns_port $ARGS_1" >> "$scripts_smartdns_tmp_conf"
    fi

    [ "$sdns_ip_change" = "1" ] && {
        echo "dualstack-ip-selection yes" >> "$scripts_smartdns_tmp_conf"
        echo "dualstack-ip-selection-threshold $sdns_ip_change_time" >> "$scripts_smartdns_tmp_conf"
    }
    [ "$sdns_force_aaaa_soa" = "1" ] && echo "force-AAAA-SOA yes" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_dualstack_ip_allow_force_aaaa" = "1" ] && [ "$sdns_cache" -gt 0 ] && \
        echo "dualstack-ip-allow-force-AAAA yes" >> "$scripts_smartdns_tmp_conf" || \
        echo "dualstack-ip-allow-force-AAAA no" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_cache_persist" = "1" ] && [ "$sdns_cache" -gt 0 ] && {
        echo "cache-persist yes" >> "$scripts_smartdns_tmp_conf"
        echo "cache-file /tmp/smartdns.cache" >> "$scripts_smartdns_tmp_conf"
    } || echo "cache-persist no" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_prefetch_domain" = "1" ] && [ "$sdns_cache" -gt 0 ] && \
        echo "prefetch-domain yes" >> "$scripts_smartdns_tmp_conf" || \
        echo "prefetch-domain no" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_ipset_timeout" = "1" ] && [ "$sdns_cache" -gt 0 ] && \
        echo "ipset-timeout yes" >> "$scripts_smartdns_tmp_conf" || \
        echo "ipset-timeout no" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_exp" = "1" ] && [ "$sdns_cache" -gt 0 ] && \
        echo "serve-expired yes" >> "$scripts_smartdns_tmp_conf" || \
        echo "serve-expired no" >> "$scripts_smartdns_tmp_conf"
    [ "$sdns_adblock" = "1" ] && [ "$sdns_cache" -gt 0 ] && \
        echo "conf-file /tmp/anti-ad-for-smartdns.conf" >> "$scripts_smartdns_tmp_conf"

    get_sdnse_conf

    local listnum=$(nvram get sdns_staticnum_x)
    for i in $(seq 1 "$listnum"); do
        j=$((i - 1))
        sdnss_enable=$(nvram get sdnss_enable_x"$j")
        if [ "$sdnss_enable" = "1" ]; then
            sdnss_name=$(nvram get sdnss_name_x"$j")
            sdnss_ip=$(nvram get sdnss_ip_x"$j")
            sdnss_port=$(nvram get sdnss_port_x"$j")
            sdnss_type=$(nvram get sdnss_type_x"$j")
            sdnss_ipc=$(nvram get sdnss_ipc_x"$j")
            sdnss_named=$(nvram get sdnss_named_x"$j")
            sdnss_non=$(nvram get sdnss_non_x"$j")
            sdnss_ipset=$(nvram get sdnss_ipset_x"$j")
            ipc="" named="" non=""
            [ "$sdnss_ipc" = "whitelist" ] && ipc="-whitelist-ip"
            [ "$sdnss_ipc" = "blacklist" ] && ipc="-blacklist-ip"
            [ -n "$sdnss_named" ] && named="-group $sdnss_named"
            [ "$sdnss_non" = "1" ] && non="-exclude-default-group"
            case $sdnss_type in
                tcp) [ "$sdnss_port" = "default" ] && port=53 || port=$sdnss_port
                     echo "server-tcp $sdnss_ip:$port $ipc $named $non" >> "$scripts_smartdns_tmp_conf" ;;
                udp) [ "$sdnss_port" = "default" ] && port=53 || port=$sdnss_port
                     echo "server $sdnss_ip:$port $ipc $named $non" >> "$scripts_smartdns_tmp_conf" ;;
                tls) [ "$sdnss_port" = "default" ] && port=853 || port=$sdnss_port
                     echo "server-tls $sdnss_ip:$port $ipc $named $non" >> "$scripts_smartdns_tmp_conf" ;;
                https) [ "$sdnss_port" = "default" ] && port=443 || port=$sdnss_port
                       echo "server-https $sdnss_ip:$port $ipc $named $non" >> "$scripts_smartdns_tmp_conf" ;;
            esac
            if [ -n "$sdnss_ipset" ]; then
                if check_ip_addr "$sdnss_ipset"; then
                    echo "ipset /$sdnss_ipset/smartdns" >> "$scripts_smartdns_tmp_conf"
                else
                    ipset add smartdns "$sdnss_ipset" 2>/dev/null || log_error "无法添加 IPSET: $sdnss_ipset"
                fi
            fi
        fi
    done

    if [ "$sdns_white" = "1" ] && [ -f "$chn_Route" ]; then
        log_info "处理白名单 IP..."
        awk '{print "whitelist-ip " $1}' "$chn_Route" > /tmp/whitelist.conf
        echo "conf-file /tmp/whitelist.conf" >> "$scripts_smartdns_tmp_conf"
    fi
    if [ "$sdns_black" = "1" ] && [ -f "$chn_Route" ]; then
        log_info "处理黑名单 IP..."
        awk '{print "blacklist-ip " $1}' "$chn_Route" > /tmp/blacklist.conf
        echo "conf-file /tmp/blacklist.conf" >> "$scripts_smartdns_tmp_conf"
    fi
}

# 生成第二服务器配置
get_sdnse_conf() {
    if [ "$sdnse_enable" = "1" ]; then
        ARGS_2="" ADDR=""
        [ "$sdnse_speed" = "1" ] && ARGS_2="$ARGS_2 -no-speed-check"
        [ -n "$sdnse_name" ] && ARGS_2="$ARGS_2 -group $sdnse_name"
        [ "$sdnse_address" = "1" ] && ARGS_2="$ARGS_2 -no-rule-addr"
        [ "$sdnse_ns" = "1" ] && ARGS_2="$ARGS_2 -no-rule-nameserver"
        [ "$sdnse_ipset" = "1" ] && ARGS_2="$ARGS_2 -no-rule-ipset"
        [ "$sdnse_as" = "1" ] && ARGS_2="$ARGS_2 -no-rule-soa"
        [ "$sdnse_ipc" = "1" ] && ARGS_2="$ARGS_2 -no-dualstack-selection"
        [ "$sdnse_cache" = "1" ] && ARGS_2="$ARGS_2 -no-cache"
        [ "$sdnse_ipv6_server" = "1" ] && ADDR="[::]"
        echo "bind $ADDR:$sdnse_port $ARGS_2" >> "$scripts_smartdns_tmp_conf"
        [ "$sdnse_tcp_server" = "1" ] && echo "bind-tcp $ADDR:$sdnse_port $ARGS_2" >> "$scripts_smartdns_tmp_conf"
    fi
}

# 下载广告过滤文件
start_ad() {
    local url=$(nvram get sdns_adblock_url)
    check_variable "sdns_adblock_url" "$url"
    for attempt in {1..3}; do
        if curl -s -o /tmp/sdnsadnew.conf --connect-timeout 10 "$url"; then
            if grep -qE '^(address=|\|\|)' /tmp/sdnsadnew.conf; then
                sed -e 's:||:address=/:' -e 's:\^:/0.0.0.0:' /tmp/sdnsadnew.conf > /tmp/anti-ad-for-smartdns.conf
                log_info "广告过滤文件下载并处理成功"
                rm -f /tmp/sdnsadnew.conf
                return 0
            else
                log_error "广告过滤文件格式无效"
            fi
        fi
        sleep $((attempt * 2))
    done
    log_error "无法下载广告过滤文件"
}

# 修改 adbyby 配置
change_adbyby() {
    local adbyby_process=$(pidof adbyby)
    adbyby_enable=$(nvram get adbyby_enable)
    adbyby_add=$(nvram get adbyby_add)
    if [ -z "$adbyby_enable" ] || [ -z "$adbyby_add" ]; then
        log_info "警告：adbyby_enable 或 adbyby_add 未定义，可能未配置 adbyby"
    fi
    if [ -n "$adbyby_process" ] && [ "$adbyby_enable" = "1" ]; then
        case $sdns_enable in
            0)
                if [ "$adbyby_add" = "1" ] && [ "$hosts_type" != "dnsmasq" ]; then
                    nvram set adbyby_add=0
                    /usr/bin/adbyby.sh switch || log_error "无法切换 adbyby 配置"
                    log_info "DNS 去广告规则: SmartDNS => DNSmasq"
                    hosts_type="dnsmasq"
                fi
                ;;
            1)
                if [ "$hosts_type" != "SmartDNS" ] && [ "$action" = "start" ]; then
                    if [ "$sdns_port" = "53" ] || [ "$adbyby_add" = "1" ] || [ "$sdns_redirect" = "2" ]; then
                        nvram set adbyby_add=1
                        /usr/bin/adbyby.sh switch || log_error "无法切换 adbyby 配置"
                        log_info "DNS 去广告规则: DNSmasq => SmartDNS"
                        hosts_type="SmartDNS"
                    fi
                fi
                ;;
        esac
    fi
}

# 修改 dnsmasq 配置
change_dnsmasq() {
    case $action in
        stop)
            sed -i '/no-resolv/d; /server=127.0.0.1#/d; /port=0/d' "$dnsmasq_Conf" || log_error "无法修改 dnsmasq 配置文件"
            if [ "$sdns_enable" = "0" ]; then
                [ "$sdns_ported" = "53" ] && log_info "已启用 DNSmasq 域名解析功能"
                [ "$sdns_redirected" = "1" ] && log_info "删除 DNSmasq 上游服务器：127.0.0.1:$sdns_ported"
            fi
            ;;
        start)
            if [ "$sdns_port" = "53" ]; then
                echo "port=0" >> "$dnsmasq_Conf" || log_error "无法写入 dnsmasq 配置文件"
                log_info "已关闭 DNSmasq 域名解析功能"
                if [ "$sdns_redirect" = "1" ]; then
                    nvram set sdns_redirect=0
                    sdns_redirect=0
                    log_info "自动修改重定向为：无"
                fi
            fi
            if [ "$sdns_redirect" = "1" ]; then
                echo "no-resolv" >> "$dnsmasq_Conf"
                echo "server=127.0.0.1#$sdns_port" >> "$dnsmasq_Conf"
                log_info "作为 DNSmasq 上游服务器：127.0.0.1:$sdns_port"
                [ "$sdnse_enable" = "1" ] && log_info "作为 DNSmasq 上游服务器：127.0.0.1:$sdnse_port"
            fi
            ;;
    esac
}

# 修改 iptables 规则
change_iptable() {
    local statu=0
    case $action in
        stop)
            if [ "$sdns_redirected" = "2" ]; then
                iptables -t nat -D PREROUTING -p tcp -d "$IPS4" --dport 53 -j REDIRECT --to-ports "$sdns_ported" >/dev/null 2>&1
                iptables -t nat -D PREROUTING -p udp -d "$IPS4" --dport 53 -j REDIRECT --to-ports "$sdns_ported" >/dev/null 2>&1
                [ -n "$IPS6" ] && {
                    ip6tables -t nat -D PREROUTING -p tcp -d "$IPS6" --dport 53 -j REDIRECT --to-ports "$sdns_ported" >/dev/null 2>&1
                    ip6tables -t nat -D PREROUTING -p udp -d "$IPS6" --dport 53 -j REDIRECT --to-ports "$sdns_ported" >/dev/null 2>&1
                }
                [ "$sdns_enable" = "0" ] && log_info "恢复重定向 $IPS4:$sdns_ported 至 xxx.xxx.xxx:53"
            fi
            [ "$sdns_redirected" = "1" ] && iptables -t nat -D PREROUTING -p udp -d "$IPS4" --dport 53 -j REDIRECT --to-ports 53 >/dev/null 2>&1
            ;;
        start)
            if [ "$sdns_redirected" != "2" ] && [ "$sdns_redirect" = "2" ]; then
                statu=1
                log_info "重定向 xxx.xxx.xxx:53 至 $IPS4:$sdns_port"
                [ "$sdnse_enable" = "1" ] && log_info "重定向 xxx.xxx.xxx:53 至 $IPS4:$sdnse_port"
            fi
            ;;
        reset)
            [ "$sdns_redirect" = "2" ] && statu=1
            [ "$sdns_redirect" = "1" ] && iptables -t nat -A PREROUTING -p udp -d "$IPS4" --dport 53 -j REDIRECT --to-ports 53 >/dev/null 2>&1
            ;;
    esac
    if [ "$statu" = "1" ]; then
        [ "$sdns_tcp_server" = "1" ] && iptables -t nat -A PREROUTING -p tcp -d "$IPS4" --dport 53 -j REDIRECT --to-ports "$sdns_port" >/dev/null 2>&1
        iptables -t nat -A PREROUTING -p udp -d "$IPS4" --dport 53 -j REDIRECT --to-ports "$sdns_port" >/dev/null 2>&1
        if [ -n "$IPS6" ] && [ "$sdns_ipv6_server" = "1" ]; then
            [ "$sdns_tcp_server" = "1" ] && ip6tables -t nat -A PREROUTING -p tcp -d "$IPS6" --dport 53 -j REDIRECT --to-ports "$sdns_port" >/dev/null 2>&1
            ip6tables -t nat -A PREROUTING -p udp -d "$IPS6" --dport 53 -j REDIRECT --to-ports "$sdns_port" >/dev/null 2>&1
        fi
    fi
}

# 启动 SmartDNS
start_smartdns() {
    [ ! -x "$smartdns_Bin" ] && log_error "SmartDNS 可执行文件不存在或不可执行"
    [ "$sdns_enable" = "0" ] && {
        nvram set sdns_enable=1
        sdns_enable=1
    }
    local smartdns_pid=$(pidof smartdns)
    [ -n "$smartdns_pid" ] && {
        kill "$smartdns_pid" 2>/dev/null
        sleep 1
        [ -n "$(pidof smartdns)" ] && log_error "无法终止 SmartDNS 进程"
    }
    change_dnsmasq
    change_adbyby
    :>"$smartdns_Ini"
    echo "$hosts_type" >> "$smartdns_Ini"
    echo "$sdns_redirect" >> "$smartdns_Ini"
    echo "$sdns_port" >> "$smartdns_Ini"
    echo "$sdnse_port" >> "$smartdns_Ini"
    [ "$sdns_redirect" = "0" ] && {
        log_info "SmartDNS 使用端口 $sdns_port"
        [ "$sdnse_enable" = "1" ] && log_info "SmartDNS 使用端口 $sdnse_port"
    }
    change_iptable
    log_info "创建 SmartDNS 配置文件..."
    ipset -N smartdns hash:net >/dev/null 2>&1 || log_error "无法创建 IPSET"
    get_sdns_conf
    for conf in "$scripts_smartdns_address_conf" "$scripts_smartdns_blacklist_ip_conf" "$scripts_smartdns_whitelist_ip_conf" "$scripts_smartdns_custom_conf"; do
        [ -r "$conf" ] && grep -v '^#' "$conf" | grep -v "^$" >> "$scripts_smartdns_tmp_conf"
    done
    sed -i '/my.router/d' "$scripts_smartdns_tmp_conf"
    echo "domain-rules /my.router/ -c none -a $IPS4 -d no" >> "$scripts_smartdns_tmp_conf"
    sort -u "$scripts_smartdns_tmp_conf" > "$scripts_smartdns_conf" || log_error "无法生成 SmartDNS 配置文件"
    local args=""
    [ "$sdns_coredump" = "1" ] && args="$args -S"
    local dnsmasq_md5=$(md5sum "$dnsmasq_Conf" | awk '{print $1}')
    "$smartdns_Bin" -f -c "$scripts_smartdns_conf" $args >/dev/null 2>&1 &
    sleep 1
    if ! pidof smartdns >/dev/null; then
        if [ "$hosts_type" = "SmartDNS" ]; then
            log_info "SmartDNS 启动失败，移除 conf-file 设置后重试..."
            sed -i '/conf-file /d' "$scripts_smartdns_conf"
            "$smartdns_Bin" -f -c "$scripts_smartdns_conf" $args >/dev/null 2>&1 &
            sleep 1
        fi
    fi
    if ! pidof smartdns >/dev/null; then
        log_error "SmartDNS 启动失败，请检查端口和配置文件"
        nvram set sdns_enable=0
        sdns_enable=0
        action="stop"
        stop_smartdns
        [ "$dnsmasq_md5" != "$(md5sum "$dnsmasq_Conf" | awk '{print $1}')" ] && {
            log_info "重启 DNSmasq 进程..."
            /sbin/restart_dhcpd >/dev/null 2>&1 || log_error "无法重启 DNSmasq"
            log_info "DNSmasq 进程已重启"
        }
        exit 1
    fi
    log_info "SmartDNS 进程已启动"
}

# 停止 SmartDNS
stop_smartdns() {
    local smartdns_pid=$(pidof smartdns)
    if [ -n "$smartdns_pid" ]; then
        kill "$smartdns_pid" 2>/dev/null
        sleep 1
        [ -n "$(pidof smartdns)" ] && log_error "无法终止 SmartDNS 进程"
        log_info "SmartDNS 进程已结束"
    fi
    change_adbyby
    change_dnsmasq
    change_iptable
    local dnsmasq_md5=$(md5sum "$dnsmasq_Conf" | awk '{print $1}')
    if [ "$dnsmasq_md5" != "$(md5sum "$dnsmasq_Conf" | awk '{print $1}')" ] && [ "$sdns_enable" = "0" ]; then
        log_info "重启 DNSmasq 进程..."
        /sbin/restart_dhcpd >/dev/null 2>&1 || log_error "无法重启 DNSmasq"
        log_info "DNSmasq 进程已重启"
    fi
    if [ -z "$(pidof smartdns)" ] && [ "$sdns_enable" = "0" ]; then
        rm -f "$smartdns_Ini"
        log_info "SmartDNS 服务器已停用"
    fi
}

# 检查 SmartDNS 配置是否有效
check_sdns_conf() {
    local sdns_port=$1
    local sdnse_port=$2
    local sdns_enable=$3
    local sdnse_enable=$4
    local sdns_redirect=$5

    # 验证端口冲突
    if [ "$sdns_enable" = "1" ] && [ "$sdnse_enable" = "1" ] && [ "$sdns_port" = "$sdnse_port" ]; then
        log_error "SmartDNS 主服务器端口 ($sdns_port) 与第二服务器端口 ($sdnse_port) 冲突"
    fi

    # 验证重定向模式（默认 sdns_port=53, sdns_redirect=1 需要特殊处理）
    if [ "$sdns_redirect" = "1" ] && [ "$sdns_port" = "53" ]; then
        log_info "SmartDNS 端口为 53，自动禁用重定向模式"
        nvram set sdns_redirect=0
        sdns_redirect=0
    fi
}

# 主函数
main() {
    action="$1"
    # 读取 NVRAM 配置
    sdns_enable=$(nvram get sdns_enable)
    sdns_name=$(nvram get sdns_name)
    sdns_port=$(sanitize_port "$(nvram get sdns_port)")
    sdns_tcp_server=$(nvram get sdns_tcp_server)
    sdns_ipv6_server=$(nvram get sdns_ipv6_server)
    sdns_redirect=$(nvram get sdns_redirect)
    sdns_cache=$(nvram get sdns_cache)
    sdns_cache_persist=$(nvram get sdns_cache_persist)
    sdns_tcp_idle_time=$(nvram get sdns_tcp_idle_time)
    sdns_rr_ttl=$(nvram get sdns_rr_ttl)
    sdns_rr_ttl_min=$(nvram get sdns_rr_ttl_min)
    sdns_rr_ttl_max=$(nvram get sdns_rr_ttl_max)
    sdns_rr_ttl_reply_max=$(nvram get sdns_rr_ttl_reply_max)
    sdns_max_reply_ip_num=$(nvram get sdns_max_reply_ip_num)
    sdns_speed=$(nvram get sdns_speed)
    sdns_speed_mode=$(nvram get sdns_speed_mode)
    sdns_address=$(nvram get sdns_address)
    sdns_ipset=$(nvram get sdns_ipset)
    sdns_ipset_timeout=$(nvram get sdns_ipset_timeout)
    sdns_as=$(nvram get sdns_as)
    sdns_ip_change=$(nvram get sdns_ip_change)
    sdns_ip_change_time=$(nvram get sdns_ip_change_time)
    sdns_dualstack_ip_allow_force_aaaa=$(nvram get sdns_dualstack_ip_allow_force_aaaa)
    sdns_force_aaaa_soa=$(nvram get sdns_force_aaaa_soa)
    sdns_force_qtype_soa=$(nvram get sdns_force_qtype_soa)
    sdns_prefetch_domain=$(nvram get sdns_prefetch_domain)
    sdns_exp=$(nvram get sdns_exp)
    sdns_exp_ttl=$(nvram get sdns_exp_ttl)
    sdns_exp_ttl_max=$(nvram get sdns_exp_ttl_max)
    sdns_exp_prefetch_time=$(nvram get sdns_exp_prefetch_time)
    sdnse_enable=$(nvram get sdnse_enable)
    sdnse_port=$(sanitize_port "$(nvram get sdnse_port)")
    sdnse_tcp_server=$(nvram get sdnse_tcp_server)
    sdnse_speed=$(nvram get sdnse_speed)
    sdnse_name=$(nvram get sdnse_name)
    sdnse_address=$(nvram get sdnse_address)
    sdnse_ns=$(nvram get sdnse_ns)
    sdns_ns=$(nvram get sdns_ns)
    sdnse_ipset=$(nvram get sdnse_ipset)
    sdnse_as=$(nvram get sdnse_as)
    sdnse_ipv6_server=$(nvram get sdnse_ipv6_server)
    sdnse_ipc=$(nvram get sdnse_ipc)
    sdnse_cache=$(nvram get sdnse_cache)
    sdns_adblock=$(nvram get sdns_adblock)
    sdns_adblock_url=$(nvram get sdns_adblock_url)
    sdns_white=$(nvram get sdns_white)
    sdns_black=$(nvram get sdns_black)
    sdns_coredump=$(nvram get sdns_coredump)

    # 验证配置
    check_sdns_conf "$sdns_port" "$sdnse_port" "$sdns_enable" "$sdnse_enable" "$sdns_redirect"

    get_ips
    read_ini
    check_md5

    case $action in
        start)
            log_info "正在启动 SmartDNS..."
            check_ss
            [ "$sdns_adblock" = "1" ] && start_ad
            start_smartdns
            log_info "SmartDNS 服务器已启动"
            echo 3 > /proc/sys/vm/drop_caches
            ;;
        stop)
            if [ -n "$(pidof smartdns)" ]; then
                [ "$sdns_enable" = "0" ] && log_info "停用 SmartDNS 服务器..."
                [ "$sdns_enable" = "1" ] && log_info "重启 SmartDNS 服务器..."
            fi
            stop_smartdns
            echo 3 > /proc/sys/vm/drop_caches
            ;;
        restart)
            if [ -n "$(nvram get adbyby_enable)" ]; then
                [ "$(nvram get adbyby_add)" = "1" ] && hosts_type="SmartDNS"
                [ "$(nvram get adbyby_add)" = "0" ] && hosts_type="dnsmasq"
            else
                hosts_type="0"
                log_info "警告：adbyby_enable 未定义，可能未启用 adbyby"
            fi
            check_ss
            stop_smartdns
            start_smartdns
            log_info "SmartDNS 服务器已重启"
            echo 3 > /proc/sys/vm/drop_caches
            ;;
        reset)
            [ "$sdns_enable" = "1" ] && change_iptable
            ;;
        *)
            echo "check"
            ;;
    esac
}

main "$@"
