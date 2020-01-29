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

#ifndef messaging_h
#define messaging_h

#include "ip_firewall.h"
#include "conn_management.h"

enum CommandType
{
    VerifyApp,         // check whether the app should be excluded from VPN
    SetFirewallRule,   // whitelist the app (based on local/remote address:port tuples)
    RemoveFirewallRule,
};

typedef struct ProcQuery
{
    enum CommandType command;
    char needs_reply;
    char app_path[PATH_MAX];
    int pid;
    int accept;
    enum RuleType rule_type;
    uint32_t id;
    uint32_t source_ip;
    uint32_t source_port;
    uint32_t dest_ip;
    uint32_t dest_port;
    uint32_t bind_ip;   // the IP to bind to
    
    // SOCK_STREAM or SOCK_DGRAM (tcp or udp)
    int socket_type;
} ProcQuery;

int send_message_nowait(struct ProcQuery *proc_query);
int send_message_and_wait_for_reply(struct ProcQuery *proc_query, struct ProcQuery *proc_response);
int pia_ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t pia_ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
int pia_ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt,
                       void *data, size_t *len);
int pia_ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt,
                       void *data, size_t len);

int register_kernel_control(struct kern_ctl_reg *kern_ctl);
int unregister_kernel_control(void);
boolean_t is_daemon_connected(void);

#endif /* messaging_h */
