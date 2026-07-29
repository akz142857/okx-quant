#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

: "${OKX_QUANT_UPLINK_INTERFACE:?missing uplink interface}"
: "${OKX_QUANT_DNS_SERVER:?missing DNS server}"

create_namespace() {
  local role="$1"
  local host_cidr="$2"
  local guest_cidr="$3"
  local namespace="okx-quant-demo-${role}"
  local host_veth="oq-${role:0:2}-host"
  local guest_veth="oq-${role:0:2}-guest"
  local gateway="${host_cidr%/*}"

  if ! ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
    ip netns add "${namespace}"
  fi
  if ! ip link show "${host_veth}" >/dev/null 2>&1; then
    ip link add "${host_veth}" type veth peer name "${guest_veth}"
    ip link set "${guest_veth}" netns "${namespace}"
  fi
  ip address replace "${host_cidr}" dev "${host_veth}"
  ip link set "${host_veth}" up
  ip netns exec "${namespace}" ip address replace "${guest_cidr}" dev "${guest_veth}"
  ip netns exec "${namespace}" ip link set lo up
  ip netns exec "${namespace}" ip link set "${guest_veth}" up
  ip netns exec "${namespace}" ip route replace default via "${gateway}"
  install -d -m 0755 "/etc/netns/${namespace}"
  printf 'nameserver %s\n' "${OKX_QUANT_DNS_SERVER}" \
    >"/etc/netns/${namespace}/resolv.conf"
}

create_namespace \
  shadow \
  "${OKX_QUANT_SHADOW_HOST_CIDR:?missing shadow host CIDR}" \
  "${OKX_QUANT_SHADOW_GUEST_CIDR:?missing shadow guest CIDR}"
create_namespace \
  active \
  "${OKX_QUANT_ACTIVE_HOST_CIDR:?missing active host CIDR}" \
  "${OKX_QUANT_ACTIVE_GUEST_CIDR:?missing active guest CIDR}"
create_namespace \
  chaos \
  "${OKX_QUANT_CHAOS_HOST_CIDR:?missing chaos host CIDR}" \
  "${OKX_QUANT_CHAOS_GUEST_CIDR:?missing chaos guest CIDR}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
for cidr in \
  "${OKX_QUANT_SHADOW_GUEST_CIDR}" \
  "${OKX_QUANT_ACTIVE_GUEST_CIDR}" \
  "${OKX_QUANT_CHAOS_GUEST_CIDR}"; do
  source_ip="${cidr%/*}"
  if ! iptables -t nat -C POSTROUTING -s "${source_ip}/32" \
    -o "${OKX_QUANT_UPLINK_INTERFACE}" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "${source_ip}/32" \
      -o "${OKX_QUANT_UPLINK_INTERFACE}" -j MASQUERADE
  fi
done
