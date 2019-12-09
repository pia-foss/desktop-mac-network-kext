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


#include <sys/kern_control.h>
#include <netinet/in.h>
#include <os/log.h>
#include <sys/systm.h>
#include <sys/kpi_socket.h>
#include <libkern/OSAtomic.h>
#include "messaging.h"
#include "conn_management.h"
#include "utils.h"
#include "ip_firewall.h"

// {set,get}sockopt() option identifiers
#define PIA_IP_SET           1
#define PIA_MSG_REPLY        2
#define PIA_REMOVE_APP       3
#define PIA_WHITELIST_PIDS   4
#define PIA_WHITELIST_PORTS  5
#define PIA_FIREWALL_STATE   6

extern lck_mtx_t        *g_message_mutex;
extern unsigned int     g_interface_ip;
extern int              daemon_pid;

static u_int32_t        ctl_unit;
static boolean_t        ctl_registered = FALSE;
static kern_ctl_ref     ctl_ref;
static boolean_t        ctl_connected = FALSE;

struct waitqueue_entry
{
    TAILQ_ENTRY(waitqueue_entry)              link;
    struct ProcQuery                          *response;
};

TAILQ_HEAD(request_wait_queue, waitqueue_entry);

// Stores message responses we get from the daemon
static struct request_wait_queue g_request_waitqueue;

// Unique identifier for each message so we can correlate requests with responses
static u_int32_t           messageId = 0;

static struct waitqueue_entry * find_in_waitqueue(struct ProcQuery *proc_response)
{
    struct waitqueue_entry * entry = NULL;
    
    TAILQ_FOREACH(entry, &g_request_waitqueue, link)
    {
        if(entry->response == proc_response)
            return entry;
    }
    
    return NULL;
}

static struct waitqueue_entry * find_in_waitqueue_by_id(uint32_t id)
{
    struct waitqueue_entry * entry = NULL;
    
    TAILQ_FOREACH(entry, &g_request_waitqueue, link)
    {
        if(entry->response->id == id)
            return entry;
        
    }
    return NULL;
}

static void cleanup_waitqueue(void)
{
    struct waitqueue_entry *entry = NULL;
    struct waitqueue_entry *next = NULL;
    
    /* cleanup, use *_SAFE variant as it allows us to delete/free without impacting traversal */
    TAILQ_FOREACH_SAFE(entry, &g_request_waitqueue, link, next)
    {
        TAILQ_REMOVE(&g_request_waitqueue, entry, link);
        pia_free(entry, sizeof(struct waitqueue_entry));
        entry = NULL;
    }
    log("Deleted all msg entries");
}

static void remove_from_waitqueue(struct waitqueue_entry *entry)
{
    if(entry)
    {
        TAILQ_REMOVE(&g_request_waitqueue, entry, link);
        pia_free(entry, sizeof(struct waitqueue_entry));
    }
}

static struct waitqueue_entry* add_to_waitqueue(struct ProcQuery *proc_response)
{
    struct waitqueue_entry *entry = pia_malloc(sizeof(struct waitqueue_entry));
    if(entry)
    {
        entry->response = proc_response;
        TAILQ_INSERT_TAIL(&g_request_waitqueue, entry, link);
        return entry;
    }
    
    return NULL;
}

static void init_waitqueue(void)
{
    TAILQ_INIT(&g_request_waitqueue);
}

boolean_t is_daemon_connected(void)
{
    return ctl_connected;
}

errno_t pia_ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    lck_mtx_lock(g_message_mutex);
    if(is_daemon_connected())
    {
        lck_mtx_unlock(g_message_mutex);
        /* Only allow one (daemon) connection at a time */
        return EBUSY;
    }
    
    ctl_unit = sac->sc_unit;
    
    char name[PATH_MAX] = {0};
    proc_selfname(name, sizeof(name));
    daemon_pid = proc_selfpid();
    
    log("Kern Control Client with pid %d and name %s connected and set ctl_unit to %d\n", daemon_pid, name, ctl_unit);
    
    ctl_connected = TRUE;
    lck_mtx_unlock(g_message_mutex);

    return 0;
}

errno_t pia_ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    lck_mtx_lock(g_message_mutex);
    ctl_connected = FALSE;
    lck_mtx_unlock(g_message_mutex);
    
    char name[PATH_MAX] = {0};
    proc_selfname(name, sizeof(name));
    log("Kern Control Client with pid %d and name %s disconnected\n", proc_selfpid(), name);
    return 0;
}

errno_t pia_ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt,
                       void *data, size_t *len)
{
    int ret = 0;
    switch(opt)
    {
    default:
        // We currently don't support any getsockopt() operations
        ret = ENOTSUP;
        break;
    }
    
    return ret;
}

static inline bool is_correct_size(char *name, size_t expected_size, size_t actual_size)
{
    if(actual_size == expected_size)
        return true;
    else
    {
        log("%s data has incorrect size! Expected %lu but received %lu", name, expected_size, actual_size);
        return false;
    }
}

errno_t pia_ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt,
                       void *data, size_t len)
{
    int ret = 0;
    char app_name[PATH_MAX] = {0};

    switch(opt)
    {
    case PIA_IP_SET:
        if(!is_correct_size("PIA_IP_SET", sizeof(uint32_t), len))
            return ret;
            
        g_interface_ip = *(int *)data;
        struct in_addr address = { .s_addr = g_interface_ip };
            
        char addstr[MAX_ADDR_LEN] = {0};
        inet_ntop(AF_INET, &address, (char*)addstr, sizeof(addstr));
        log("ip set to: \"%s\"\n", addstr);
        break;
    case PIA_MSG_REPLY:
        if(!is_correct_size("PIA_MSG_REPLY", sizeof(struct ProcQuery), len))
            return ret;
            
        struct ProcQuery *response = (struct ProcQuery *)(data);
            
        // Correlate with the message_id in the daemon and the one in send_message_and_wait_for_reply
        log_debug("message_id: %d Response received, accept %d", response->id, response->accept);
            
        lck_mtx_lock(g_message_mutex);
        struct waitqueue_entry *entry = find_in_waitqueue_by_id(response->id);
        if(entry)
        {
            // Update the waitqueue entry with the response it's been waiting for
            *entry->response = *response;
            
            // Now we can remove it from the waitqueue (since it's no longer waiting, it has the response)
            remove_from_waitqueue(entry);
            lck_mtx_unlock(g_message_mutex);
            
            // Alert waiting threads there's new data available
            wakeup(&g_request_waitqueue);
        }
        else
        {
            lck_mtx_unlock(g_message_mutex);
        }
        break;
    case PIA_REMOVE_APP:
        if(!is_correct_size("PIA_REMOVE_APP", sizeof(app_name), len))
            return ret;
            
        strncpy_(app_name, (char*)data, len);
        remove_app_from_fastpath(app_name);
        log("Removing app: %s from fastpath", app_name);
        break;
    case PIA_WHITELIST_PIDS:
        if(!is_correct_size("PIA_WHITELIST_PIDS", MAX_WHITELISTED_PIDS * sizeof(int), len))
            return ret;
            
        set_whitelisted_pids((int *)data);
        break;
    case PIA_WHITELIST_PORTS:
        if(!is_correct_size("PIA_WHITELIST_PORTS", MAX_WHITELISTED_PORTS * sizeof(struct WhitelistPort), len))
            return ret;
            
        set_whitelisted_ports(data);
        break;
    case PIA_FIREWALL_STATE:
        if(!is_correct_size("PIA_FIREWALL_STATE", sizeof(struct firewall_state_t), len))
            return ret;
 
        update_firewall_state((struct firewall_state_t *)data);
        break;
    default:
        ret = ENOTSUP;
        break;
    }
    return ret;
}

int send_message_nowait(struct ProcQuery *proc_query)
{
    // Unique identifier for messages
    OSIncrementAtomic(&messageId);
    proc_query->needs_reply = 0;
    proc_query->id = messageId;
    
    if(!is_daemon_connected())
    {
        // Logging here that we failed to find a connection to send a message is really noisy
        // So let's not log in this situation, and only log when we encounter an error on sending (as in ctl_enqueuedata)
        return -1;
    }
    
    // ctl_enqueuedata is not threadsafe
    lck_mtx_lock(g_message_mutex);
    int err = ctl_enqueuedata(ctl_ref, ctl_unit, (void*)proc_query, sizeof(ProcQuery), CTL_DATA_EOR);
    lck_mtx_unlock(g_message_mutex);
    
    log_debug("message_id: %d Sent message", proc_query->id);
    
    if(err)
    {
        log("Could not enqueue data, error code %d\n", err);
        return -1;
    }
    
    return 0;
}

int send_message_and_wait_for_reply(struct ProcQuery *proc_query, struct ProcQuery *proc_response)
{
    // 200000000 nanoseconds = 0.2 seconds
    // Timeout for our condition variable
    static struct timespec ts = { .tv_sec = 0, .tv_nsec =  200000000 };
    
    // Unique identifier for messages
    OSIncrementAtomic(&messageId);
    
    // Also setting the proc_response->id so we can find the empty response
    // object later when we search the waitqueue (the response id will always correspond to the request id)
    proc_query->id = proc_response->id = messageId;
    proc_query->needs_reply = 1;
    
    if(!is_daemon_connected())
    {
        // Logging here that we failed to find a connection to send a message is really noisy
        // So let's not log in this situation, and only log when we encounter an error on sending (as in ctl_enqueuedata)
        return -1;
    }
    
    char name[PATH_MAX] = {0};
    proc_selfname(name, sizeof(name));

    lck_mtx_lock(g_message_mutex);
    int err = ctl_enqueuedata(ctl_ref, ctl_unit, (void*)proc_query, sizeof(ProcQuery), CTL_DATA_EOR);

    if(err)
    {
        log("Could not enqueue data, error code %d\n", err);
        lck_mtx_unlock(g_message_mutex);
        return -1;
    }
    
    char *socket_type = proc_query->socket_type == SOCK_DGRAM ? "UDP" : "TCP";
    
    log_debug("message_id: %d Sent message; waiting for response pid %d name %s socket_type %s %d",
              proc_query->id, proc_selfpid(), name, socket_type, proc_query->socket_type);
    
    add_to_waitqueue(proc_response);
    
    // While still in the wait queue, keep looping
    while(find_in_waitqueue(proc_response))
    {
        // EWOULDBLOCK is returned when the condition var times out, in this case we don't want to retry, but just error out
        if(msleep(&g_request_waitqueue, g_message_mutex, 0, "send_message_and_wait_for_reply",  &ts) == EWOULDBLOCK)
        {
            // Paranoia: double-check that pia_ctl_set() didn't acquire the lock just before us and already removed the response and freed the memory.
            // This protects against possible double-free (in remove_from_waitqueue) and ultra-rare Kernel panic
            // In order for this to occur the response must arrive just before our condition var is about to timeout
            struct waitqueue_entry *entry = find_in_waitqueue(proc_response);
            if(entry)
            {
                log("message_id: %d msleep: Waited too long pid %d name %s", proc_query->id, proc_selfpid(), name);
            
                // We're no longer waiting since we timed out
                remove_from_waitqueue(entry);
                lck_mtx_unlock(g_message_mutex);
                return -1;
            }
        }
        
        // re-check we're still connected to daemon socket (otherwise we could get stuck if daemon crashes)
        if(!is_daemon_connected())
        {
            log("No connection to daemon, pid %d", proc_selfpid());
            // The mutex is re-acquired on waking, so we must release again here before returning
            lck_mtx_unlock(g_message_mutex);
            return -1 ;
        }
    }
    
    // We have the mutex again at this point (acquired upon waking)
    
    // The proc_response object is updated with the response by the pia_ctl_set() method
    
    log_debug("message_id: %d Response processed! pid %d name %s", proc_response->id, proc_selfpid(), name);
    
    lck_mtx_unlock(g_message_mutex);
    
    return 0;
}

int unregister_kernel_control()
{
    // Connection to ctl must be manually ended, we cannot force it. So the daemon must kill
    // the connection to the kext
    // TODO: send a shutdown message to the daemon, telling it to close the ctl socket?
    if(is_daemon_connected())
    {
        log("A control socket is still open, the daemon must close it before unloading the kext.");
        return KERN_FAILURE;
    }
    else
    {
        if(ctl_registered)
        {
            errno_t error_ctl = ctl_deregister(ctl_ref);
            if(error_ctl)
                log("Exit code for ctl_deregister is %d\n", error_ctl);
        }
        ctl_registered = FALSE;
    }
    
    cleanup_waitqueue();
    
    return KERN_SUCCESS;
}

int register_kernel_control(struct kern_ctl_reg *kern_ctl)
{
    int ret = 0;
    
    if((ret = ctl_register(kern_ctl, &ctl_ref)))
    {
        log("Could not register kernel control, error code %d\n", ret);
        return KERN_FAILURE;
    }
    
    ctl_registered = TRUE;
    
    init_waitqueue();
    
    return KERN_SUCCESS;
}
