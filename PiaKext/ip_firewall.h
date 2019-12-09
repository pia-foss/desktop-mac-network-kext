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

#ifndef ip_firewall_h
#define ip_firewall_h

#define MAX_WHITELISTED_PIDS 500
#define MAX_WHITELISTED_PORTS 2000

struct packet_info
{
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    char     socket_type;
};

struct firewall_state_t
{
    bool killswitch_active;
    bool allow_lan;
};

struct WhitelistPort
{
    uint32_t source_ip;
    uint32_t source_port;
};

boolean_t is_lan_ip(uint32_t dest_address);
void get_packet_info(mbuf_t *data, struct packet_info *info);

// Render a packet as a string of the form: source_ip:port -> dest_ip:port
// Only valid for TCP/UDP packets
void packet_to_string(char* result, int resultsize, struct packet_info *packet);
void set_whitelisted_pids(int *array);
void set_whitelisted_ports(struct WhitelistPort *array);

boolean_t is_whitelisted_pid(int pid);
boolean_t is_whitelisted_port(uint32_t source_ip, uint32_t source_port);

void update_firewall_state(struct firewall_state_t *updated_firewall_state);

boolean_t is_allow_lan_on(void);
boolean_t is_killswitch_active(void);
boolean_t is_loopback(uint32_t dest_address);

#endif /* ip_firewall_h */
