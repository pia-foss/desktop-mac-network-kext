// Copyright (c) 2019 London Trust Media Incorporated
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
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>

#include <netinet/kpi_ipfilter.h>
#include <sys/kpi_mbuf.h>
#include <i386/endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/proc.h>

#include <netinet/in.h>
#include <kern/task.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>

#include <libkern/OSMalloc.h>

#include <sys/kern_control.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <libkern/OSAtomic.h>

#include "PiaKext.h"
#include "utils.h"
#include "conn_management.h"
#include "messaging.h"
#include "ip_firewall.h"

lck_mtx_t               *g_connection_mutex = NULL;
lck_mtx_t               *g_message_mutex = NULL;
lck_mtx_t               *g_firewall_mutex = NULL;
static lck_grp_t        *g_mutex_group = NULL;
static boolean_t        g_filter_tcp_registered = FALSE;
static boolean_t        g_filter_udp_registered = FALSE;
static boolean_t        g_filter_tcp6_registered = FALSE;
static boolean_t        g_filter_udp6_registered = FALSE;
static boolean_t        g_ip_filter_registered  = FALSE;
static boolean_t        g_ip_filter_detached    = FALSE;
static ipfilter_t       ip_filter_ref;
unsigned int            g_interface_ip = 0;
int                     daemon_pid = -1;
OSMallocTag             g_osm_tag;

#define PIA_FLT_TCP_HANDLE       'pia0'
#define PIA_FLT_UDP_HANDLE       'pia1'
#define PIA_FLT_TCP6_HANDLE      'pia2'
#define PIA_FLT_UDP6_HANDLE      'pia3'

static int bind_socket_to_address(socket_t so, int port, unsigned int address)
{
    if(!address)
        /* No address, return error code */
        return -1;
    
    struct sockaddr_in newAddr = {0};
    newAddr.sin_len = sizeof(newAddr); // yes this field is needed
    newAddr.sin_family = AF_INET;
    newAddr.sin_port = port;
    newAddr.sin_addr.s_addr = address;
    
    int err = 0;
    if((err = sock_bind(so, (struct sockaddr*)&newAddr)))
    {
        log("Error binding socket: code %d\n", err);
    }
    
    return err;
}

static errno_t rebind_excluded_socket(socket_t so, int port, struct conn_entry *entry)
{
    assert(entry);  // Checked by caller
    // New entry; not rebound yet (ensured by caller)
    assert(!entry->desc.bound);
    assert(entry->desc.source_ip == 0);
    assert(entry->desc.source_port == 0);

    // scratch space for storing addresses for logging
    char addr[MAX_ADDR_LEN] = {0};
    struct sockaddr_in source = {0};

    sock_getsockname(so, (struct sockaddr*)&source, sizeof(struct sockaddr));
    store_ip_and_port_addr(&source, addr, sizeof(addr));
    log("id %d Source before rebinding is: %s", entry->desc.id, addr);

    if(bind_socket_to_address(so, port, g_interface_ip))
    {
        // Error rebinding socket, it's logged in bind_socket_to_address() so
        // let's early-exit
        return ENOPOLICY;
    }
    sock_getsockname(so, (struct sockaddr*)&source, sizeof(struct sockaddr));

    entry->desc.bound = true;
    entry->desc.source_ip = source.sin_addr.s_addr;
    entry->desc.source_port = source.sin_port;
    entry->desc.dest_ip = 0;
    entry->desc.dest_port = 0;

    store_ip_and_port_addr(&source, addr, sizeof(addr));
    log("id %d Source after rebinding is: %s", entry->desc.id, addr);

    return 0;
}

static errno_t pia_attach(void **cookie, socket_t so)
{
    char                 name[PATH_MAX];
    int pid              = 0;
    int socket_type      = 0;
    int err              = 0;
    
    *cookie = NULL;
    
    if(!g_interface_ip)
    {
        // No interface IP is set, do not attach
        return ENOPOLICY;
    }
    
    // Do not attach if daemon is not connected
    if(!is_daemon_connected())
        return ENOPOLICY;
    
    // Do not attach to daemon sockets OR the kernel (pid == 0)
    if(proc_selfpid() == daemon_pid || proc_selfpid() == 0)
        return ENOPOLICY;
    
    // Is our socket TCP or UDP?
    if((err = sock_gettype(so, NULL, &socket_type, NULL)))
    {
        log("Error: Could not get socket type: code %d\n", err);
        
        // Give up
        return ENOPOLICY;
    }
    
    proc_selfname(name, PATH_MAX);
    pid = proc_selfpid();

    // Look for an existing entry based on PID, if we find one then we can
    // skip verification with the daemon (fast path)
    struct conn_entry *entry = NULL;
    if((entry = check_for_existing_pid_and_add_conn(pid, socket_type)))
    {
        log("id %d [Fastpath] Attaching to %s socket. name: %s, pid: %d\n", entry->desc.id, socket_type == SOCK_DGRAM ? "UDP" : "TCP", name, pid);

        *cookie = (void*)entry;
        return 0;
    }
    else
    {
        ProcQuery proc_query = { .command = VerifyApp, .pid = proc_selfpid(), .socket_type = socket_type };
        ProcQuery proc_response = {0};
        
        if(send_message_and_wait_for_reply(&proc_query, &proc_response))
            return ENOPOLICY;
        
        if(!proc_response.accept)
        {
            // Verification was denied (the process was not in the exclusions list)
            // so we do not bind to this socket
            return ENOPOLICY;
        }
        
        // Add the connection to our connections list (this entry also serves as the cookie for our socket filter)
        struct conn_entry *entry = add_conn(proc_response.app_path, proc_response.pid, socket_type, sflt_connection);
        
        if(!entry)
            return ENOPOLICY;

        log("id %d Attaching to %s socket. name: %s, pid: %d\n", entry->desc.id, socket_type == SOCK_DGRAM ? "UDP" : "TCP", name, pid);

        *cookie = (void*)entry;
    }
    
    return 0;
}

static void pia_detach(void *cookie, socket_t so)
{
    if(cookie)
    {
        struct conn_entry* entry = (struct conn_entry *)cookie;
        log("id %d Detach %s app_entry is: name: %s, pid: %d\n", entry->desc.id, entry->desc.socket_type == SOCK_DGRAM ? "UDP" : "TCP", entry->desc.name, entry->desc.pid);
        
        // This removes the entry from the list of connections
        // and frees the memory associated with the entry.
        conn_remove(entry);
    }
    else
    {
        log("No cookie was found for this socket!\n");
    }
    
    cookie = NULL;
    
    return;
}

static void pia_unregistered(sflt_handle handle)
{
    switch(handle)
    {
        case PIA_FLT_TCP_HANDLE:
            log("Unregistered TCP filter (pia0)");
            g_filter_tcp_registered = FALSE;
            break;
        case PIA_FLT_UDP_HANDLE:
            log("Unregistered UDP filter (pia1)");
            g_filter_udp_registered = FALSE;
            break;
        case PIA_FLT_TCP6_HANDLE:
            log("Unregistered TCP/IPv6 filter (pia2)");
            g_filter_tcp6_registered = FALSE;
            break;
        case PIA_FLT_UDP6_HANDLE:
            log("Unregistered UDP/IPv6 filter (pia3)");
            g_filter_udp6_registered = FALSE;
            break;
        default:
            log("Unregistered UNKNOWN filter with handle %d\n", handle);
            break;
    }
}

// Check a socket to see if we should bind it to the physical interface.
//
// The socket is bound if all of the following are true:
// - The socket is connecting to an IPv4 address
// - The socket belongs to an excluded app (cookie is valid)
// - The socket hasn't been previously bound or observed as bound (avoids
//   calling sock_getsockname() for every UDP data packet)
// - The socket isn't connecting to a loopback address
static errno_t check_socket_rebind(void *cookie, socket_t so,
                                   const struct sockaddr *to,
                                   const char *callback_name)
{
    struct conn_entry* entry = (struct conn_entry *)cookie;

    // If the socket isn't connecting to an IPv4 address, we can't do anything
    // with it.
    if(!to || to->sa_family != AF_INET || to->sa_len < sizeof(struct sockaddr_in))
        return 0;
    const struct sockaddr_in *to_in = (const struct sockaddr_in *)to;

    // If this socket belongs to an excluded app, pia_attach() created a
    // connection entry and set it as the cookie.
    //
    // If it's an excluded app, and hasn't already been bound, check if we
    // should rebind it based on the destination address.
    if(entry && !entry->desc.bound)
    {
        // Check if the socket was already bound
        char addr[MAX_ADDR_LEN] = {0};
        struct sockaddr_in source = {0};
        sock_getsockname(so, (struct sockaddr*)&source, sizeof(struct sockaddr));
        // If the socket already has a bound source, update our connection
        // entry, don't try to bind again.
        if(source.sin_addr.s_addr || source.sin_port)
        {
            store_ip_and_port_addr(&source, addr, sizeof(addr));
            log("id %d Already bound (%s): %s", entry->desc.id, callback_name, addr);
            entry->desc.bound = true;
            entry->desc.source_ip = source.sin_addr.s_addr;
            entry->desc.source_port = source.sin_port;
            return 0;
        }

        // If the destination address is loopback, do not bind to the
        // physical interface.
        if(IN_LOOPBACK(ntohl(to_in->sin_addr.s_addr)))
        {
            store_ip_and_port_addr(to_in, addr, sizeof(addr));
            log("id %d Connecting to localhost (%s): %s", entry->desc.id, callback_name, addr);
            // The source address will _probably_ be 127.0.0.1 but we can't be
            // sure of that, we may observe this socket again when it sends data
            // and observe that it has been bound by connect().
            return 0;
        }

        log("id %d Rebinding (%s)", entry->desc.id, callback_name);
        // The socket does not have a bound source address yet - bind to the
        // physical interface since this is an excluded app.
        errno_t bindErr = rebind_excluded_socket(so, 0, entry);
        if(bindErr)
            return bindErr;
    }

    return 0;
}

static errno_t pia_connect_out(void *cookie, socket_t so, const struct sockaddr *to)
{
    return check_socket_rebind(cookie, so, to, "connect_out");
}

static errno_t pia_data_out(void *cookie, socket_t so, const struct sockaddr *to,
                            mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
    return check_socket_rebind(cookie, so, to, "data_out");
}

// If an excluded app listens on a socket or receives incoming data, remember
// the bound address so we can permit it in the packet filter.
static errno_t check_inbound_socket(void *cookie, socket_t so,
                                    const char *callback_name)
{
    struct conn_entry* entry = (struct conn_entry *)cookie;

    if(entry && !entry->desc.bound)
    {
        char addr[MAX_ADDR_LEN] = {0};
        struct sockaddr_in source = {0};
        sock_getsockname(so, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
        store_ip_and_port_addr(&source, addr, sizeof(addr));

        log("id %d Inbound socket (%s): %s", entry->desc.id, callback_name, addr);
        entry->desc.bound = true;
        entry->desc.source_ip = source.sin_addr.s_addr;
        entry->desc.source_port = source.sin_port;
    }

    return 0;
}

static errno_t pia_listen(void *cookie, socket_t so)
{
    return check_inbound_socket(cookie, so, "listen");
}

static errno_t pia_connect_in(void *cookie, socket_t so, const struct sockaddr *from)
{
    // Often, inbound TCP connections have already been handled by listen(), but
    // this filter might be the first one to observe a socket if the app was
    // already listening when PIA was started.
    return check_inbound_socket(cookie, so, "connect_in");
}

static errno_t pia_data_in(void *cookie, socket_t so, const struct sockaddr *from,
                           mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
    return check_inbound_socket(cookie, so, "data_in");
}

// Listening on an IPv6 "any" address allows inbound IPv4 connections, record
// these so they can be allowed through the firewall.
static errno_t check_inbound_socket6(void *cookie, socket_t so, const char *callback_name)
{
    struct conn_entry* entry = (struct conn_entry*)cookie;
    if(entry && !entry->desc.bound)
    {
        struct sockaddr_in6 source = {0};
        sock_getsockname(so, (struct sockaddr*)&source, sizeof(struct sockaddr_in6));

        // Even if we don't end up recording the IPv6 address (if it's not
        // "any"), the socket is bound and we can stop checking.
        entry->desc.bound = true;

        struct in6_addr any_addr = {0};
        if(memcmp(source.sin6_addr.s6_addr, any_addr.s6_addr, sizeof(any_addr.s6_addr)) == 0)
        {
            log("id %d Inbound to IPv6 any with port %d, treat as IPv4 any (%s)",
                entry->desc.id, source.sin6_port, callback_name);
            entry->desc.source_ip = 0;
            entry->desc.source_port = source.sin6_port;
        }
        else
        {
            log("id %d Inbound to IPv6 with port %d, ignored (%s)", entry->desc.id,
                source.sin6_port, callback_name);
        }
    }

    return 0;
}

static errno_t pia_listen6(void *cookie, socket_t so)
{
    return check_inbound_socket6(cookie, so, "listen6");
}

static errno_t pia_connect_in6(void *cookie, socket_t so, const struct sockaddr *from)
{
    return check_inbound_socket6(cookie, so, "connect_in6");
}

static errno_t pia_data_in6(void *cookie, socket_t so, const struct sockaddr *from,
                           mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
    return check_inbound_socket6(cookie, so, "data_in6");
}

#define ALLOW_PACKET 0
#define BLOCK_PACKET ENETUNREACH

// Our custom IP firewall:
// * Default policy (ALLOW or BLOCK) is determined by state of killswitch - if killswitch is on then we BLOCK by default
// * Always allow loopback
// * Allow LAN ips only if allow_lan is on
// * Allow non TCP/UDP traffic only if it's from the Kernel or it's from an excluded App
// * Allow any daemon or daemon child traffic (i.e pia-daemon and pia-openvpn)
// * Allow whitelisted PIDs (i.e pre-existing connections for excluded apps)
// * Allow whitelisted ports (i.e pre-existing ports sent from the daemon)
// * Apply the default policy to everything else
static errno_t pia_ipfilter_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    // The default policy is determined by the killswitch  - if killswitch is on we block everything by default, otherwise we allow everything
    errno_t DEFAULT_POLICY = is_killswitch_active() ? BLOCK_PACKET : ALLOW_PACKET;
    
    if(!is_daemon_connected())
        return ALLOW_PACKET;
    
    struct packet_info packet = {0};
    
    get_packet_info(data, &packet);
    
    // Always allow loopback
    if(is_loopback(packet.dest_ip))
        return ALLOW_PACKET;
    
    // Allow LAN, Link-local, multicast, broadcast, etc (if allowLAN is on)
    if(is_lan_ip(packet.dest_ip))
        return is_allow_lan_on() ? ALLOW_PACKET : BLOCK_PACKET;
    
    // Allow anything not trying to bind to the physical interface - i.e the tunnel
    // (Interfaces other than the tunnel are blocked by the pf firewall)
    if(packet.source_ip != g_interface_ip)
        return ALLOW_PACKET;

    // A socket-type == 0 indicates a non TCP/UDP packet (most likely it'll be ICMP)
    // Without this check a simple "ping -S 192.168.1.40 1.1.1.1" could escape the VPN
    if(!packet.socket_type)
    {
        // Allow a non TCP/UDP packet if it's either sent from the kernel or sent from an excluded app
        // We can't check for is_whitelisted_pid() here as we don't have enough information to create a conn entry
        // For that we need a source port as well - as it's much harder for a nefarious process to spoof a source port + whitelisted pid than just a whitelisted pid
        if(proc_selfpid() == 0 || find_conn_by_pid(proc_selfpid(), any_connection))
            return ALLOW_PACKET;
        else
            return DEFAULT_POLICY;
    }
    
    /* All packets after this point are guaranteed to be TCP or UDP */
    
    char *socket_type_string = packet.socket_type == SOCK_DGRAM ? "UDP" : "TCP";
    
    // Scratch space for storing packet string
    char packet_string[MAX_ADDR_LEN] = {0};
    
    // Scratch space for process name
    char process_name[PATH_MAX] = {0};
    
    // Allow apps we already exclude
    if(matches_conn(packet.source_ip, packet.source_port, proc_selfpid()))
    {
        return ALLOW_PACKET;
    }
    
    // Add new exclusion for daemon and its child processes (i.e openvpn), also for any whitelisted PIDs (i.e pre-existing processes sent
    // by by the daemon)
    else if(proc_selfpid() == daemon_pid || proc_selfppid() == daemon_pid || is_whitelisted_pid(proc_selfpid()))
    {
        proc_selfname(process_name, sizeof(process_name));
        struct conn_entry *entry = add_conn(process_name, proc_selfpid(), packet.socket_type, preexisting_connection);
        entry->desc.source_ip = packet.source_ip;
        entry->desc.source_port = packet.source_port;
        
        packet_to_string(packet_string, sizeof(packet_string), &packet);
        log("Adding Kernel Firewall %s exception! pid: %d %s %s", socket_type_string, proc_selfpid(), process_name, packet_string);
        return ALLOW_PACKET;
    }

    // Allow the kernel to send to any whitelisted port from an existing
    // process.  This happens for TCP sockets, such as the SYN/ACK for a new
    // inbound connection or occasionally on outgoing connections.
    else if(proc_selfpid() == 0 && is_whitelisted_port(packet.source_ip, packet.source_port))
    {
        return ALLOW_PACKET;
    }
    
    // We block all other TCP/UDP packets (but only if killswitch is on)
    else if(is_killswitch_active())
    {
        proc_selfname(process_name, sizeof(process_name));
        packet_to_string(packet_string, sizeof(packet_string), &packet);
        log("Blocking a %s packet for pid %d %s %s", socket_type_string, proc_selfpid(), process_name, packet_string);
        return BLOCK_PACKET;
    }
    
    return DEFAULT_POLICY;
}

#undef ALLOW_PACKET
#undef BLOCK_PACKET

static void pia_ipfilter_detach(void *cookie)
{
    log("Detached IP filter.");
    g_ip_filter_detached = TRUE;
}
    
/* For TCP sockets */
static struct sflt_filter socket_tcp_filter = {
    PIA_FLT_TCP_HANDLE,
    SFLT_GLOBAL,
    BUNDLE_ID,
    pia_unregistered,
    pia_attach,
    pia_detach,
    NULL,
    NULL,
    NULL,
    pia_data_in,
    pia_data_out,
    pia_connect_in,
    pia_connect_out,
    NULL,
    NULL,
    NULL,
    pia_listen,
    NULL
};

/* For UDP sockets */
static struct sflt_filter socket_udp_filter = {
    PIA_FLT_UDP_HANDLE,
    SFLT_GLOBAL,
    BUNDLE_ID,
    pia_unregistered,
    pia_attach,
    pia_detach,
    NULL,
    NULL,
    NULL,
    pia_data_in,
    pia_data_out,
    NULL,
    pia_connect_out,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

/* For TCP/IPv6 sockets */
static struct sflt_filter socket_tcp6_filter = {
    PIA_FLT_TCP6_HANDLE,
    SFLT_GLOBAL,
    BUNDLE_ID,
    pia_unregistered,
    pia_attach,
    pia_detach,
    NULL,
    NULL,
    NULL,
    pia_data_in6,
    NULL,
    pia_connect_in6,
    NULL,
    NULL,
    NULL,
    NULL,
    pia_listen6,
    NULL
};

/* For UDP/IPv6 sockets */
static struct sflt_filter socket_udp6_filter = {
    PIA_FLT_UDP6_HANDLE,
    SFLT_GLOBAL,
    BUNDLE_ID,
    pia_unregistered,
    pia_attach,
    pia_detach,
    NULL,
    NULL,
    NULL,
    pia_data_in6,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

/* Our communication channel to the daemon (kernel control) */
static struct kern_ctl_reg g_kern_ctl_reg = {
    BUNDLE_ID,
    0,
    0,
    CTL_FLAG_PRIVILEGED,
    0,
    0,
    pia_ctl_connect,
    pia_ctl_disconnect,
    NULL,
    pia_ctl_set,
    pia_ctl_get
};

static struct ipf_filter ip_filter = {
    NULL,      // No cookie needed
    BUNDLE_ID,
    NULL,
    pia_ipfilter_output,
    pia_ipfilter_detach
};

void cleanup_mutexes()
{
    
    if(g_connection_mutex) lck_mtx_free(g_connection_mutex, g_mutex_group);
    if(g_message_mutex) lck_mtx_free(g_message_mutex, g_mutex_group);
    if(g_firewall_mutex) lck_mtx_free(g_firewall_mutex, g_mutex_group);
    if(g_mutex_group) lck_grp_free(g_mutex_group);
    if(g_osm_tag) OSMalloc_Tagfree(g_osm_tag);
    
    g_connection_mutex = NULL;
    g_message_mutex = NULL;
    g_firewall_mutex = NULL;
    g_mutex_group = NULL;
    g_osm_tag = NULL;
}

int setup_mutexes()
{
    g_osm_tag = OSMalloc_Tagalloc(BUNDLE_ID, OSMT_DEFAULT);
    if(!g_osm_tag)
        return -1;
    
    /* allocate mutex group and a mutex to protect global data. */
    g_mutex_group = lck_grp_alloc_init(BUNDLE_ID, LCK_GRP_ATTR_NULL);
    if(!g_mutex_group)
        return -1;
    
    g_connection_mutex = lck_mtx_alloc_init(g_mutex_group, LCK_ATTR_NULL);
    if(!g_connection_mutex)
        return -1;
    
    g_message_mutex = lck_mtx_alloc_init(g_mutex_group, LCK_ATTR_NULL);
    if(!g_connection_mutex)
        return -1;
    
    g_firewall_mutex = lck_mtx_alloc_init(g_mutex_group, LCK_ATTR_NULL);
    if(!g_firewall_mutex)
        return -1;
    
    return 0;
}

void unregister_socket_filter(boolean_t *registered, boolean_t *started,
                              sflt_handle handle, const char *name)
{
    if(*registered == TRUE && !*started)
    {
        errno_t error_sflt = sflt_unregister(handle);
        if(error_sflt)
            log("Exit code for sflt_unregister %s is %d\n", name, error_sflt);
        *started = TRUE;
    }
}

void check_socket_unregistered(boolean_t *registered, int *result, const char *name)
{
    if(*result == 0 && *registered)
    {
        log("The %s socket filter is still registered", name);
        *result = -1;
    }
}

int unregister_socket_filters()
{
    static boolean_t filter_tcp_unregister_started = FALSE;
    static boolean_t filter_udp_unregister_started = FALSE;
    static boolean_t filter_tcp6_unregister_started = FALSE;
    static boolean_t filter_udp6_unregister_started = FALSE;

    unregister_socket_filter(&g_filter_tcp_registered, &filter_tcp_unregister_started, PIA_FLT_TCP_HANDLE, "tcp");
    unregister_socket_filter(&g_filter_udp_registered, &filter_udp_unregister_started, PIA_FLT_UDP_HANDLE, "udp");
    unregister_socket_filter(&g_filter_tcp6_registered, &filter_tcp6_unregister_started, PIA_FLT_TCP6_HANDLE, "tcp6");
    unregister_socket_filter(&g_filter_udp6_registered, &filter_udp6_unregister_started, PIA_FLT_UDP6_HANDLE, "udp6");

    int result = 0;
    check_socket_unregistered(&g_filter_tcp_registered, &result, "TCP");
    check_socket_unregistered(&g_filter_udp_registered, &result, "UDP");
    check_socket_unregistered(&g_filter_tcp6_registered, &result, "TCP6");
    check_socket_unregistered(&g_filter_udp6_registered, &result, "UDP6");
    
    return result;
}

int unregister_ip_filter()
{
    if(g_ip_filter_registered)
    {
        ipf_remove(ip_filter_ref);
        g_ip_filter_registered = FALSE;
    }

    if(!g_ip_filter_detached)
    {
        log("The IP filter is still registered.");
        return -1;
    }
    
    return 0;
}

int register_socket_filter(struct sflt_filter *filter, int domain, int type, int protocol, boolean_t *registered, const char *name)
{
    int ret;
    if((ret = sflt_register(filter, domain, type, protocol)))
    {
        log("Could not register %s socket filter, error code %d\n", name, ret);
    }
    else
    {
        *registered = TRUE;
    }
    return ret;
}

kern_return_t PiaKext_start(kmod_info_t * ki, void * d)
{
    init_conn_list();
    
    if(setup_mutexes())
        goto bail;
    
    if(register_kernel_control(&g_kern_ctl_reg))
        goto bail;
    
    int ret;
    if((ret = register_socket_filter(&socket_tcp_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP, &g_filter_tcp_registered, "tcp")) ||
       (ret = register_socket_filter(&socket_udp_filter, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &g_filter_udp_registered, "udp")) ||
       (ret = register_socket_filter(&socket_tcp6_filter, PF_INET6, SOCK_STREAM, IPPROTO_TCP, &g_filter_tcp6_registered, "tcp6")) ||
       (ret = register_socket_filter(&socket_udp6_filter, PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &g_filter_udp6_registered, "udp6")))
    {
        goto bail;
    }
    
    if((ret = ipf_addv4(&ip_filter, &ip_filter_ref)))
    {
        log("Could not register IP filter, error code: %d\n", ret);
        goto bail;
    }
    
    g_ip_filter_registered = TRUE;
    
    log("Successfully started PiaKext. Version %s", PIAKEXT_VERSION);
    
    return KERN_SUCCESS;
    
bail:
    cleanup_mutexes();
    unregister_kernel_control();
    
    if(g_filter_tcp_registered)
        sflt_unregister(PIA_FLT_TCP_HANDLE);
    
    if(g_filter_udp_registered)
        sflt_unregister(PIA_FLT_UDP_HANDLE);

    if(g_filter_tcp6_registered)
        sflt_unregister(PIA_FLT_TCP6_HANDLE);

    if(g_filter_udp6_registered)
        sflt_unregister(PIA_FLT_UDP6_HANDLE);
    
    if(g_ip_filter_registered)
        ipf_remove(ip_filter_ref);
    
    return KERN_FAILURE;
}

kern_return_t PiaKext_stop(kmod_info_t * ki, void * d)
{
    log("Attempting to stop PiaKext.");
    // Connection to ctl must be manually ended, we cannot force it. So the daemon must kill
    // the connection to the kext
    if(unregister_kernel_control())
        return EBUSY;
    
    if(unregister_socket_filters())
        return EBUSY;
    
    if(unregister_ip_filter())
        return EBUSY;
    
    /* cleanup */
    cleanup_conn_list();
    cleanup_mutexes();
    
    log("Successfully stopped PiaKext. Version %s", PIAKEXT_VERSION);
    
    return KERN_SUCCESS;
}
