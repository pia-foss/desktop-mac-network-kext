// Copyright (c) 2020 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/kpi_mbuf.h>
#include <string.h>
#include "utils.h"
#include "ip_firewall.h"

// PIDS belonging to pre-existing processes
// A pre-existing process is an excluded process that is already connected so we must exclude it
// via the IP filter firewall rather than a socket filter.
static int whitelisted_pids[MAX_WHITELISTED_PIDS] = {0};
// TCP addresses/ports belonging to pre-existing processes.  This whitelist
// allows the kernel to send on these ports (it only affects the kernel, the
// process itself is covered by the PID whitelist).  The array is terminated
// with an entry that has source_port=0 (source_ip can be 0 normall though)
static struct WhitelistPort whitelisted_ports[MAX_WHITELISTED_PORTS] = {0};

static struct WhitelistSubnet whitelisted_subnets[MAX_WHITELISTED_SUBNETS] = {0};

static struct firewall_state_t firewall_state = {0};

extern lck_mtx_t               *g_firewall_mutex;

// A whitelisted PID is a PID of a pre-existing process we do not have a socket fliter
// attached to that we want to allow through the firewall.
boolean_t is_whitelisted_pid(int pid)
{
    if(pid == 0)
        return false;

    lck_mtx_lock(g_firewall_mutex);
    // End the loop when we (1) find a matching pid (2) reach the end of the array (3) encounter a 0 PID (a sentinel value indicating the end)
    for(int i = 0; i != NUM_ELEMENTS(whitelisted_pids) && whitelisted_pids[i] != 0; ++i)
    {
        if(pid == whitelisted_pids[i])
        {
            lck_mtx_unlock(g_firewall_mutex);
            return true;
        }
    }
    lck_mtx_unlock(g_firewall_mutex);
    return false;
}

void set_whitelisted_pids(int *array)
{
    lck_mtx_lock(g_firewall_mutex);
    // size is enforced/checked by the caller
    memcpy(whitelisted_pids, array, sizeof(whitelisted_pids));

    log("whitelisted_pids:");
    for(int i = 0; i != NUM_ELEMENTS(whitelisted_pids) && whitelisted_pids[i] != 0; ++i)
    {
        log("%d", whitelisted_pids[i]);
    }
    lck_mtx_unlock(g_firewall_mutex);
}

boolean_t is_whitelisted_port(uint32_t source_ip, uint32_t source_port)
{
    lck_mtx_lock(g_firewall_mutex);
    for(int i=0;
        i != NUM_ELEMENTS(whitelisted_ports) &&
            whitelisted_ports[i].source_port != 0;
        ++i)
    {
        // A whitelist entry of 0.0.0.0:<port> matches any IP address with that
        // port
        if((whitelisted_ports[i].source_ip == 0 || source_ip == whitelisted_ports[i].source_ip) &&
           source_port == whitelisted_ports[i].source_port)
        {
            lck_mtx_unlock(g_firewall_mutex);
            return true;
        }
    }

    lck_mtx_unlock(g_firewall_mutex);
    return false;
}

void set_whitelisted_ports(const struct WhitelistPort *array)
{
    lck_mtx_lock(g_firewall_mutex);
    memcpy(whitelisted_ports, array, sizeof(whitelisted_ports));
    char addr[MAX_ADDR_LEN] = {0};
    struct sockaddr_in source = {0};
    log("whitelisted_ports:");
    for(int i=0;
        i != NUM_ELEMENTS(whitelisted_ports) &&
            whitelisted_ports[i].source_port != 0;
        ++i)
    {
        source.sin_addr.s_addr = whitelisted_ports[i].source_ip;
        source.sin_port = whitelisted_ports[i].source_port;
        store_ip_and_port_addr(&source, addr, sizeof(addr));
        log("%s", addr);
    }
    lck_mtx_unlock(g_firewall_mutex);
}

void set_whitelisted_subnets(const struct WhitelistSubnet *array)
{
    lck_mtx_lock(g_firewall_mutex);
    // size is enforced/checked by the caller
    memcpy(whitelisted_subnets, array, sizeof(whitelisted_subnets));

    log("whitelisted_subnets:");
    for(int i = 0; i != NUM_ELEMENTS(whitelisted_subnets) && whitelisted_subnets[i].network_ip != 0; ++i)
    {
        struct sockaddr_in sin = { .sin_addr.s_addr = htonl(whitelisted_subnets[i].network_ip) };

        char addstr[MAX_ADDR_LEN] = {0};
        inet_ntop(AF_INET, &sin.sin_addr, addstr, sizeof(addstr));
        log("%s/%d", addstr, whitelisted_subnets[i].prefix_length);
    }
    lck_mtx_unlock(g_firewall_mutex);
}

boolean_t is_in_subnet(uint32_t dest_ip, const struct WhitelistSubnet *subnet)
{
    if(!subnet || subnet->prefix_length > 32)
        // Invalid prefix
        return false;

    uint32_t mask = 0xFFFFFFFF << (32 - subnet->prefix_length);

    // Check that the destination ip falls within the subnet
    return (subnet->network_ip & mask) == (dest_ip & mask);
}

boolean_t is_whitelisted_subnet(uint32_t dest_ip)
{
    lck_mtx_lock(g_firewall_mutex);
    for(int i=0;
        i != NUM_ELEMENTS(whitelisted_subnets) &&
            whitelisted_subnets[i].network_ip != 0;
        ++i)
    {

        if(is_in_subnet(dest_ip, &whitelisted_subnets[i]))
        {
            lck_mtx_unlock(g_firewall_mutex);
            return true;
        }
    }

    lck_mtx_unlock(g_firewall_mutex);
    return false;
}

void packet_to_string(char* result, int resultsize, struct packet_info *packet)
{
    char source_buf[MAX_ADDR_LEN] = {0};
    char dest_buf[MAX_ADDR_LEN] = {0};
    struct sockaddr_in address = {0};

    address.sin_addr.s_addr = packet->source_ip; address.sin_port = packet->source_port;
    store_ip_and_port_addr(&address, source_buf, sizeof(source_buf));

    address.sin_addr.s_addr = packet->dest_ip; address.sin_port = packet->dest_port;
    store_ip_and_port_addr(&address, dest_buf, sizeof(dest_buf));

    snprintf(result, resultsize, "%s -> %s", source_buf, dest_buf);
}

void get_packet_info(mbuf_t *data, struct packet_info *info)
{
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct ip *ip = (struct ip*)mbuf_data(*data);
    unsigned char *ptr = (unsigned char*)ip;
    unsigned char *layer4_hdr = ptr + (ip->ip_hl << 2);

    switch(ip->ip_p)
    {
    case IPPROTO_TCP:
        tcp = (struct tcphdr*)layer4_hdr;
        info->source_port = tcp->th_sport;
        info->dest_port   = tcp->th_dport;
        info->socket_type = SOCK_STREAM;
        break;
    case IPPROTO_UDP:
        udp = (struct udphdr*)layer4_hdr;
        info->source_port = udp->uh_sport;
        info->dest_port   = udp->uh_dport;
        info->socket_type = SOCK_DGRAM;
        break;

    default:
        // If the packet is not TCP/UDP
        info->socket_type = 0;
    }

    info->source_ip = ip->ip_src.s_addr;
    info->dest_ip   = ip->ip_dst.s_addr;
}

boolean_t is_sockaddr_in(const struct sockaddr *addr)
{
    return addr && addr->sa_family == AF_INET &&
        addr->sa_len >= sizeof(struct sockaddr_in);
}

struct sockaddr_in *as_sockaddr_in(struct sockaddr *addr)
{
    return is_sockaddr_in(addr) ? (struct sockaddr_in*)addr : NULL;
}

const struct sockaddr_in *as_sockaddr_in_c(const struct sockaddr *addr)
{
    return is_sockaddr_in(addr) ? (const struct sockaddr_in*)addr : NULL;
}

boolean_t is_loopback(uint32_t dest_address)
{
    // Host order address
    uint32_t ho_address = ntohl(dest_address);

    return IN_LOOPBACK(ho_address);
}

boolean_t is_lan_ip(uint32_t dest_address)
{
    // Host order address
    uint32_t ho_address = ntohl(dest_address);

    // CLASS_D -> 224.* 239.255.* (multicast)
    // INADDR_BROADCAST -> 255.255.255.255 for broadcast
    return (IN_LINKLOCAL(ho_address) || IN_PRIVATE(ho_address) || IN_CLASSD(ho_address) || INADDR_BROADCAST == ho_address);
}

boolean_t is_sockaddr_in6(const struct sockaddr *addr)
{
    return addr && addr->sa_family == AF_INET6 &&
        addr->sa_len >= sizeof(struct sockaddr_in6);
}

struct sockaddr_in6 *as_sockaddr_in6(struct sockaddr *addr)
{
    return is_sockaddr_in6(addr) ? (struct sockaddr_in6*)addr : NULL;
}

const struct sockaddr_in6 *as_sockaddr_in6_c(const struct sockaddr *addr)
{
    return is_sockaddr_in6(addr) ? (const struct sockaddr_in6*)addr : NULL;
}

boolean_t is_loopback_6(const struct in6_addr *addr)
{
    if(!addr)
        return 0;
    return IN6_IS_ADDR_LOOPBACK(addr);
}

boolean_t is_lan_6(const struct in6_addr *addr)
{
    if(!addr)
        return 0;
    return IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_SITELOCAL(addr) ||
           IN6_IS_ADDR_MULTICAST(addr);
}

void update_firewall_state(struct firewall_state_t *updated_firewall_state)
{
    lck_mtx_lock(g_firewall_mutex);
    firewall_state = *updated_firewall_state;
    lck_mtx_unlock(g_firewall_mutex);
    log("Updating firewall state to: killswitch_active %d, allowLAN %d routeDefault %d isConnected %d", firewall_state.killswitch_active, firewall_state.allow_lan, firewall_state.route_default, firewall_state.is_connected);
}

boolean_t is_allow_lan_on(void)
{
    lck_mtx_lock(g_firewall_mutex);
    boolean_t result = firewall_state.allow_lan;
    lck_mtx_unlock(g_firewall_mutex);
    return result;
}

boolean_t is_killswitch_active(void)
{
    lck_mtx_lock(g_firewall_mutex);
    boolean_t result = firewall_state.killswitch_active;
    lck_mtx_unlock(g_firewall_mutex);
    return result;
}

boolean_t is_vpn_default_route(void)
{
    lck_mtx_lock(g_firewall_mutex);
    boolean_t result = firewall_state.route_default;
    lck_mtx_unlock(g_firewall_mutex);
    return result;
}

boolean_t is_vpn_connected(void)
{
    lck_mtx_lock(g_firewall_mutex);
    boolean_t result = firewall_state.is_connected;
    lck_mtx_unlock(g_firewall_mutex);
    return result;
}
