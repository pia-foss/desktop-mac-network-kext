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

#include <sys/socket.h>
#include <netinet/in.h>
#include <os/log.h>
#include <sys/systm.h>
#include <libkern/OSMalloc.h>
#include "utils.h"

extern OSMallocTag g_osm_tag;

char *strrchr_(const char *s, int c)
{
    const char *found, *p;
    
    c = (unsigned char) c;
    
    /* Since strchr is fast, we use it rather than the obvious loop.  */
    
    if (c == '\0')
        return strchr(s, '\0');
    
    found = NULL;
    while ((p = strchr(s, c)) != NULL)
    {
        found = p;
        s = p + 1;
    }
    
    return (char *) found;
}

char *strncpy_(char *dst, const char*src, size_t n)
{
    char *temp = dst;
    while(n-- && (*dst++ = *src++))
        ;
    
    return temp;
}

char *basename(const char *filename)
{
    char *p = strrchr_(filename, '/');
    return p ? p + 1 : (char *) filename;
}

void store_ip_and_port_addr(const struct sockaddr_in* addr, char *buf, int buf_size)
{
    char addstr[256];
    inet_ntop(AF_INET, &addr->sin_addr, (char*)addstr, sizeof(addstr));
    snprintf(buf, buf_size, "%s:%d", addstr, ntohs(addr->sin_port));
}

bool starts_with(const char *a, const char *b)
{
    if (strncmp(a, b, strlen(b)) == 0)
        return true;
    return false;
}

void *pia_malloc(uint32_t size)
{
    void *address = OSMalloc(size, g_osm_tag);
    
    if(!address)
    {
        log("Cannot allocate memory, OSMalloc failed!");
        return NULL;
    }
    
    bzero(address, size);
    
    return address;
}

void pia_free(void *address, uint32_t size)
{
    OSFree(address, size, g_osm_tag);
}
