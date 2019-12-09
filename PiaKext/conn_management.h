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

#ifndef conn_management_h
#define conn_management_h

enum connection_type_t
{
    sflt_connection,         // Connections added by our socket filter
    preexisting_connection,  // Connections added by the IP filter (these are pre-existing connections)
    any_connection           // Either of above
};

struct connection_descriptor
{
    char name[PATH_MAX];
    char path[PATH_MAX];
    int pid;
    
    // Once a source address has been observed for a socket (whether we bound it
    // or we observed that it has been bound), this is set, so we'll stop
    // checking this socket (important to avoid a check for every data_in /
    // data_out hook).
    //
    // For IPv4, this always results in source_ip/source_port being set, but for
    // IPv6, we can only store an "any" address.
    boolean_t bound;
    uint32_t source_ip;
    uint32_t source_port;
    uint32_t dest_ip;
    uint32_t dest_port;
    uint32_t id;
    enum connection_type_t connection_type;
    
    // SOCK_STREAM or SOCK_DGRAM (tcp or udp)
    int socket_type;
};

struct conn_entry
{
    TAILQ_ENTRY(conn_entry)   link;
    struct connection_descriptor        desc;
};

struct conn_entry * add_conn(const char *app_path, int pid, int socket_type, enum connection_type_t connection_type);
void init_conn_list(void);
struct conn_entry * find_conn_by_pid(int pid, enum connection_type_t connection_type);
// Test if a packet matches a known connection (used for the packet filter).
// * If a known connection is bound to 0.0.0.0:<port> (any interface), it
//   matches any source IP.
// * The port must always match.
// * If the specified pid is nonzero, it must match the PID for the known
//   connection.
bool matches_conn(uint32_t source_ip, uint32_t source_port, int pid);
void cleanup_conn_list(void);
void conn_remove(struct conn_entry *entry);
void remove_app_from_fastpath(const char *app_path);
struct conn_entry * check_for_existing_pid_and_add_conn(int pid, int socket_type);

#endif /* app_management_h */
