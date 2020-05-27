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

#include <sys/socket.h>
#include <netinet/in.h>
#include <os/log.h>
#include <sys/systm.h>
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include "conn_management.h"
#include "utils.h"

const uint32_t no_requested_port = htonl((uint32_t)-1);

extern lck_mtx_t        *g_connection_mutex;

// Uniquely identify each connection
// This value increments for each new connection
// This is not vital information, so it's not the end of the world if it ultimately overflows and wraps around
u_int32_t               connectionId = 1;

TAILQ_HEAD(pia_connection_list, conn_entry);

static struct pia_connection_list g_conn_list;

void init_conn_list()
{
    TAILQ_INIT(&g_conn_list);
}

void cleanup_conn_list()
{
    struct conn_entry *entry = NULL, *next_entry = NULL;
    lck_mtx_lock(g_connection_mutex);

    // Cleanup
    for(entry = TAILQ_FIRST(&g_conn_list); entry; entry = next_entry)
    {
        next_entry = TAILQ_NEXT(entry, link);
        TAILQ_REMOVE(&g_conn_list, entry, link);
        pia_free(entry, sizeof(struct conn_entry));
    }
    log("Deleted all connection entries");
    lck_mtx_unlock(g_connection_mutex);
}

void conn_remove(struct conn_entry *entry)
{
    if(!entry)
        return;

    lck_mtx_lock(g_connection_mutex);
    // Remove entry from list
    TAILQ_REMOVE(&g_conn_list, entry, link);

    log("id %d Removing an instance of: name %s with pid %d\n", entry->desc.id, entry->desc.name, entry->desc.pid);

    // Free the memory for the entry
    pia_free(entry, sizeof(struct conn_entry));

    lck_mtx_unlock(g_connection_mutex);
}

static struct conn_entry *__internal_add_conn(const char *app_path, int pid,
                                              uint32_t bind_ip, int socket_type,
                                              enum connection_type_t connection_type,
                                              enum RuleType rule_type)
{
    struct conn_entry* entry = pia_malloc(sizeof(struct conn_entry));
    if(!entry) return NULL;

    // Increment the connection ID
    // A unique identifier for each connection so we can trace connection life-cycles in the logs
    OSIncrementAtomic(&connectionId);

    strncpy_(entry->desc.name, basename(app_path), PATH_MAX);
    strncpy_(entry->desc.path, app_path, PATH_MAX);
    entry->desc.id = connectionId;
    entry->desc.pid = pid;
    entry->desc.bound = false;
    entry->desc.source_ip = 0;
    entry->desc.source_port = 0;
    entry->desc.dest_ip = 0;
    entry->desc.dest_port = 0;
    entry->desc.bind_ip = bind_ip;
    entry->desc.requested_port = no_requested_port;
    entry->desc.connection_type = connection_type;
    entry->desc.rule_type = rule_type;

    // Should be SOCK_STREAM or SOCK_DGRAM
    entry->desc.socket_type = socket_type;

    return entry;
}

/* Thread safe version of above, exposed externally */
struct conn_entry *add_conn(const char *app_path, int pid, uint32_t bind_ip,
                            int socket_type,
                            enum connection_type_t connection_type,
                            enum RuleType rule_type)
{
    struct conn_entry* entry = __internal_add_conn(app_path, pid, bind_ip,
                                                   socket_type, connection_type,
                                                   rule_type);
    if(!entry) return NULL;

    lck_mtx_lock(g_connection_mutex);
    TAILQ_INSERT_TAIL(&g_conn_list, entry, link);
    lck_mtx_unlock(g_connection_mutex);
    log("id %d Adding: name %s with pid %d\n", entry->desc.id, entry->desc.name, entry->desc.pid);

    return entry;
}

static struct conn_entry *
__internal_find_conn_by_pid(int pid, enum connection_type_t connection_type)
{
    struct conn_entry *entry, *next_entry;
    for(entry = TAILQ_FIRST(&g_conn_list); entry; entry = next_entry)
    {
        next_entry = TAILQ_NEXT(entry, link);
        if(entry->desc.pid == pid && (entry->desc.connection_type == connection_type || entry->desc.connection_type == any_connection))
        {
            return entry;
        }
    }
    return NULL;
}

/* Thread safe version of above, exposed externally */
struct conn_entry *
find_conn_by_pid(int pid, enum connection_type_t connection_type)
{
    lck_mtx_lock(g_connection_mutex);
    struct conn_entry *entry = __internal_find_conn_by_pid(pid, connection_type);
    lck_mtx_unlock(g_connection_mutex);
    return entry;
}

bool matches_conn(uint32_t source_ip, uint32_t source_port, int pid)
{
    bool foundMatch = false;
    struct conn_entry *entry, *next_entry;
    lck_mtx_lock(g_connection_mutex);
    for(entry = TAILQ_FIRST(&g_conn_list); entry; entry = next_entry)
    {
        next_entry = TAILQ_NEXT(entry, link);

        // The port must always match (this also ensures that connections that
        // don't have a source yet don't match all packets; source port is 0)
        if(source_port != entry->desc.source_port)
            continue;
        // If the connection is bound to a specific IP address, it must match
        // (listening sockets could be bound to any interface, which matches any
        // source IP)
        if(entry->desc.source_ip && source_ip != entry->desc.source_ip)
            continue;
        // If a PID was given, it must match (kernel is allowed to send on
        // behalf of any process)
        if(pid && pid != entry->desc.pid)
            continue;

        // Found a match
        foundMatch = true;
        break;
    }
    lck_mtx_unlock(g_connection_mutex);
    return foundMatch;
}
