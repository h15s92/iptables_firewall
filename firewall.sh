#!/bin/bash
set -euo pipefail

# =========================
# CONFIG
# =========================

INTERNET_IF="eth0"
LOCAL_IF="eth1"
SSH_PORT="22"
ENABLE_LOGGING="yes"

# Общий whitelist:
# этим IP/FQDN разрешен входящий трафик с интернета
ALLOW_LIST=(
    "1.2.3.4"
    "example.com"
)

# Админы:
# этим IP/FQDN разрешено всё входящее, включая SSH
ADMIN_LIST=(
    "5.6.7.8"
    "admin.example.com"
)

# =========================
# HELPERS
# =========================

log() {
    echo "[FW] $1"
}

is_ip_address() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done

    return 0
}

resolve_to_ips() {
    local item="$1"

    if is_ip_address "$item"; then
        echo "$item"
        return 0
    fi

    dig +short A "$item" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u || true
}

add_allow_rule_for_ip() {
    local ip="$1"
    local comment="$2"

    iptables -A INPUT -i "$INTERNET_IF" -s "$ip" -j ACCEPT -m comment --comment "$comment"
}

add_admin_rule_for_ip() {
    local ip="$1"
    local comment="$2"

    # Разрешаем весь входящий трафик от администратора
    iptables -A INPUT -i "$INTERNET_IF" -s "$ip" -j ACCEPT -m comment --comment "$comment ALL"

    # Явно оставляем SSH как отдельное правило для читаемости
    iptables -A INPUT -i "$INTERNET_IF" -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT -m comment --comment "$comment SSH"
}

allow_list_items() {
    local mode="$1"
    shift
    local items=("$@")

    for item in "${items[@]}"; do
        [[ -n "${item// }" ]] || continue

        local resolved_ips
        resolved_ips="$(resolve_to_ips "$item")"

        if [[ -z "$resolved_ips" ]]; then
            log "WARNING: '$item' не удалось резолвить"
            continue
        fi

        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue

            if [[ "$mode" == "admin" ]]; then
                add_admin_rule_for_ip "$ip" "ADMIN:$item->$ip"
                log "ADMIN allowed: $item -> $ip"
            else
                add_allow_rule_for_ip "$ip" "ALLOW:$item->$ip"
                log "ALLOW allowed: $item -> $ip"
            fi
        done <<< "$resolved_ips"
    done
}

allow_loopback() {
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    log "Loopback allowed"
}

allow_established_related() {
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log "Established/Related allowed"
}

allow_local_network() {
    iptables -A INPUT  -i "$LOCAL_IF" -j ACCEPT
    iptables -A OUTPUT -o "$LOCAL_IF" -j ACCEPT
    log "All local traffic allowed on $LOCAL_IF"
}

allow_current_ssh_client_temporarily() {
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local current_ssh_ip
        current_ssh_ip="$(awk '{print $1}' <<< "$SSH_CLIENT")"

        if is_ip_address "$current_ssh_ip"; then
            iptables -A INPUT -i "$INTERNET_IF" -p tcp -s "$current_ssh_ip" --dport "$SSH_PORT" -j ACCEPT -m comment --comment "TEMP current SSH client"
            log "Temporary SSH protection added for current client: $current_ssh_ip"
        fi
    fi
}

enable_logging() {
    if [[ "$ENABLE_LOGGING" == "yes" ]]; then
        iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTABLES_INPUT_DROP: " --log-level 4
        log "Drop logging enabled"
    fi
}

reset_firewall() {
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    log "Firewall rules flushed"
}

set_default_policies() {
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    log "Default policies set: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT"
}

show_rules() {
    echo
    echo "================ IPTABLES ================"
    iptables -L -n -v --line-numbers
    echo "=========================================="
}

# =========================
# MAIN
# =========================

reset_firewall

# Базовые разрешения
allow_current_ssh_client_temporarily
allow_loopback
allow_established_related
allow_local_network

# Белые списки
allow_list_items "allow" "${ALLOW_LIST[@]}"
allow_list_items "admin" "${ADMIN_LIST[@]}"

# Логирование перед default DROP
enable_logging

# Политики по умолчанию
set_default_policies

log "Firewall rules applied successfully"
show_rules
