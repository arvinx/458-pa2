/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void make_and_send_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_packet, int icmp_type, int icmp_code);

void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int packet_len,
 uint32_t target, enum sr_ethertype type, int rt_icmp_not_found);

const char int_iface_name[] = "eth1";
const char ext_iface_name[] = "eth2";

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    
} /* -- sr_init -- */

/* send an arp reply to an arp request given by packet and arp_header */
void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_header,
                    char* interface, uint8_t * packet, unsigned int len) {
        
    struct sr_if* interface_sr_if = sr_get_interface(sr, interface);
    sr_arp_hdr_t* arp_reply_header = (struct sr_arp_hdr*) malloc(sizeof(struct sr_arp_hdr));
    
    arp_reply_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_reply_header->ar_pro = htons(ethertype_ip);
    arp_reply_header->ar_op = htons(arp_op_reply);

    arp_reply_header->ar_hln = ETHER_ADDR_LEN;
    arp_reply_header->ar_pln = sizeof(uint32_t);

    arp_reply_header->ar_sip = interface_sr_if->ip;
    arp_reply_header->ar_tip = arp_header->ar_sip;
    memcpy(arp_reply_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_reply_header->ar_sha, interface_sr_if->addr, ETHER_ADDR_LEN);
    
    /* construct frame and send packet */

    sr_ethernet_hdr_t* ether_header =  (sr_ethernet_hdr_t*)packet;

    memcpy(ether_header->ether_dhost, ether_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_shost, interface_sr_if->addr, ETHER_ADDR_LEN);
    
    memcpy(packet, ether_header, sizeof(struct sr_ethernet_hdr));
    memcpy(packet + sizeof(struct sr_ethernet_hdr),
           arp_reply_header, sizeof(struct sr_arp_hdr));
    
    sr_send_packet(sr, packet, len, interface);
    
    free(arp_reply_header);
}

/* returns the sr_rt entry in routing table that has longest prefix match */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_rt* cur = sr->routing_table;
    struct sr_rt* longest = NULL;
    unsigned long match_len = 0;
    struct in_addr addr;
    addr.s_addr = ip_dst;

    while(cur != NULL) {
        if (((cur->dest.s_addr & cur->mask.s_addr) == (addr.s_addr & cur->mask.s_addr))
             & (match_len <= cur->mask.s_addr)){
            match_len = cur->mask.s_addr;
            longest = cur;
        }
        cur = cur->next;
    }
    return longest;
}

/* returns 1 if target_ip matches any ip's in if_list */
int is_in_interface_lst(struct sr_instance* sr, uint32_t ip_dst){
    
    struct sr_if* cur = sr->if_list;
    
    while (cur != NULL) {
        if (cur->ip == ip_dst) {
            return 1;
        }
        cur = cur->next;
    }
    return 0;
}

void make_and_send_icmp_echo(struct sr_instance* sr, sr_ip_hdr_t* ip_packet) {
     /* echo reply */ 

    uint32_t src = ip_packet->ip_src;
    uint32_t dest = ip_packet->ip_dst;
    uint32_t target = src;
    ip_packet->ip_src = dest;
    ip_packet->ip_dst = src;

    sr_icmp_t0_hdr_t* icmp_header = (sr_icmp_t0_hdr_t*) ((uint8_t*)ip_packet + 4*ip_packet->ip_hl);
    icmp_header->icmp_type = 0;
    icmp_header->icmp_type = 0;

    if (sr->nat_instance) {
        /* check if server is pinging client instead of just eth2 */
        struct sr_nat* nat = sr->nat_instance;
        struct sr_nat_mapping* m = nat->mappings;
        if (m) {
            printf("CUR ID EXT IN MAPPING: %d  AUX_INT: %d \n", ntohs(m->aux_ext), ntohs(m->aux_int));
        } else {
            printf("NO MAPPING FOUND :(\n");
        }
        struct sr_nat_mapping* mapping = sr_nat_lookup_external(sr->nat_instance, icmp_header->id, nat_mapping_icmp);     
        if (mapping != NULL) {
            ip_packet->ip_src = src;
            target = mapping->ip_int;
            ip_packet->ip_dst = mapping->ip_int;
            printf(" NEW IP DEST FROM SERVER TO CLIENT: \n");
            icmp_header->id = mapping->aux_int;
            free(mapping);
        }
    } 

    ip_packet->ip_len = htons(4*ip_packet->ip_hl + sizeof(sr_icmp_t0_hdr_t));
    ip_packet->ip_sum = 0;
    icmp_header->icmp_sum = 0;
    ip_packet->ip_sum = cksum(ip_packet, 4*ip_packet->ip_hl);

    uint16_t ip_len = ntohs(ip_packet->ip_len);
    icmp_header->icmp_sum = cksum(icmp_header, ip_len - 4*ip_packet->ip_hl);

    printf(" ********** SENDING ECHO REPLY \n");
    print_hdr_ip((uint8_t*)ip_packet);
    printf("ECHO SENDING NEW ID: %d SEQ: %d\n", htons(icmp_header->id), htons(icmp_header->sequence_num)); 

    send_packet(sr, (uint8_t*)ip_packet, ip_len, target, ethertype_ip, 0);
}

/* helper method to construct icmp requests that are not echo */
void make_and_send_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_packet, int icmp_type, int icmp_code) {

    struct sr_icmp_t3_hdr icmp_header;
    struct sr_ip_hdr* ip_header = 
    (struct sr_ip_hdr*) malloc(sizeof(struct sr_ip_hdr));

    icmp_header.icmp_type = icmp_type;
    icmp_header.icmp_code = icmp_code;
    icmp_header.unused = 0;
    memcpy(icmp_header.data, ip_packet, ICMP_DATA_SIZE);

    ip_header->ip_dst = ip_packet->ip_src;
    ip_header->ip_id = ip_packet->ip_id;
    ip_header->ip_v = 4;
    ip_header->ip_p = ip_protocol_icmp;
    ip_header->ip_tos = 0;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_ttl = 50;

    struct sr_rt* rt_entry = longest_prefix_match(sr, ip_header->ip_dst);
    if (rt_entry == NULL) {
        /* ignore */
        return;
    }
    struct sr_if *inf = sr_get_interface(sr, (const char*)rt_entry->interface);
    ip_header->ip_src = inf->ip;

    unsigned int len = 4*ip_header->ip_hl + sizeof(struct sr_icmp_t3_hdr);
    ip_header->ip_len = htons(len);
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, 4*ip_header->ip_hl);

    icmp_header.icmp_sum = 0;
    icmp_header.icmp_sum = cksum(&icmp_header, sizeof(struct sr_icmp_t3_hdr));

    uint8_t* packet_to_send = malloc(len);
    memcpy(packet_to_send, ip_header, 4*ip_header->ip_hl);
    memcpy(packet_to_send + 4*ip_header->ip_hl, &icmp_header, len - 4*ip_header->ip_hl);

    send_packet(sr, packet_to_send, len, ip_packet->ip_src, ethertype_ip, 0);
}

/* wrapper to send ip packets and arp packets. wraps them in ether frame*/
void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int packet_len,
    uint32_t target, enum sr_ethertype type, int rt_icmp_not_found) {

    struct sr_rt* rt_entry = longest_prefix_match(sr, target);

    if (rt_entry == NULL) {
        if (rt_icmp_not_found == 1)
            make_and_send_icmp(sr, (sr_ip_hdr_t*) packet, 3, 0);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, rt_entry->interface);
    struct sr_arpentry* arp_item = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

    if (arp_item) {
        struct sr_ethernet_hdr ether_header;

        ether_header.ether_type = htons(type);

        memcpy(ether_header.ether_dhost, arp_item->mac, ETHER_ADDR_LEN);
        memcpy(ether_header.ether_shost, iface->addr, ETHER_ADDR_LEN);

        uint8_t* ether_packet = malloc(packet_len + sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet, &ether_header, sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet + sizeof(struct sr_ethernet_hdr), packet, packet_len);

        sr_send_packet(sr, ether_packet, packet_len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);
        
        free(ether_packet);

    } else if(type == ethertype_arp && (((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))) {
        struct sr_ethernet_hdr ether_header;

        ether_header.ether_type = htons(type);

        memset(ether_header.ether_dhost, 255, ETHER_ADDR_LEN);
        memcpy(ether_header.ether_shost, iface->addr, ETHER_ADDR_LEN);

        uint8_t* ether_packet = malloc(packet_len + sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet, &ether_header, sizeof(struct sr_ethernet_hdr));
        memcpy(ether_packet + sizeof(struct sr_ethernet_hdr), packet, packet_len);

        sr_send_packet(sr, ether_packet, packet_len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);

        free(ether_packet);

    } else {
        uint8_t* ip_packet_copy = malloc(packet_len);
        memcpy(ip_packet_copy, packet, packet_len);

        struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr,
         ip_packet_copy, packet_len, rt_entry->interface);
        handle_arpreq(sr, arp_request);

        free(ip_packet_copy);
    }

    if (arp_item) {
        free(arp_item);
    }

}

/* returns 0 if no modification made to icmp/tcp headers, 1 if icmp header
   modified, 2 if tcp header modified */
void nat_translate_forwarding(struct sr_instance* sr, uint8_t * packet, sr_ip_hdr_t* ip_packet) {
    struct sr_rt* rtable_entry = longest_prefix_match(sr, ip_packet->ip_src);
    /* if it's sourced from the client behind nat we need to do a nat translation for icmp 0 */

    if (strcmp(rtable_entry->interface, int_iface_name) == 0) {
        /* packet is from client (src) if recieved on (eth1) */
        if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_icmp)  {
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
            /* client sending icmp echo request to server */
            if (icmp_header->icmp_type == 8) {
                printf("Forwarding a type 8 icmp request \n");
                sr_icmp_t0_hdr_t* icmp = (sr_icmp_t0_hdr_t*) icmp_header;
                print_hdr_icmp((uint8_t*)icmp);

                struct sr_nat_mapping* mapping = sr_nat_lookup_internal(sr->nat_instance, ip_packet->ip_src,
                 icmp->id, nat_mapping_icmp);
                if (!mapping) {
                    printf("INSERTING MAPPING FOR ID: %d\n", ntohs(icmp->id));
                    mapping = sr_nat_insert_mapping(sr->nat_instance, ip_packet->ip_src, icmp->id, nat_mapping_icmp);
                }

                printf("MAPPING AUX_EXT IS ID: %d\n", ntohs(mapping->aux_ext));

                icmp->id = mapping->aux_ext;

                free(mapping);

                /* rewrite source ip as eth2 */
                struct sr_if* iface = sr_get_interface(sr, ext_iface_name);
                ip_packet->ip_src = iface->ip;
                printf("NEW SOURCE IP: "); 
                print_hdr_ip((uint8_t*)ip_packet);

                memcpy((uint8_t*)ip_packet + 4*ip_packet->ip_hl, icmp, sizeof(sr_icmp_t0_hdr_t));

                printf("FORWARDING THIS NEW ID: %d SEQ: %d\n", ntohs(icmp->id), ntohs(icmp->sequence_num));
            }
        } else if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_tcp) {
            /* it's a tcp packet */
            sr_tcp_hdr_t* tcp_header = (sr_tcp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
            printf("FORWARDING RECIEVED TCP FROM CLIENT: src port: %d dest_port: %d seq no: %d ack no: %d flags: %d\n",
                ntohs(tcp_header->source_port), ntohs(tcp_header->dest_port), ntohs(tcp_header->seq_number),
                ntohs(tcp_header->ack_number), tcp_header->flags);

            /* TODO lookup external for inbound syn from server that is on 6 sec wait */
            struct sr_nat_mapping* mapping = sr_nat_lookup_internal(sr->nat_instance, ip_packet->ip_src,
             tcp_header->source_port, nat_mapping_tcp);
            struct sr_nat_connection* conn;

            if (!mapping) {
                printf("INSERTING TCP MAPPING FOR PORT: %d\n", ntohs(tcp_header->source_port));
                mapping = sr_nat_insert_mapping(sr->nat_instance, ip_packet->ip_src, tcp_header->source_port, nat_mapping_tcp);
                conn = sr_nat_insert_tcp_connection(sr->nat_instance, ip_packet->ip_src, tcp_header->source_port,
                 ip_packet->ip_dst, tcp_header->dest_port, OUTBOUND_SENT_SYN);
            } else {
                conn = sr_nat_lookup_tcp_connection(sr->nat_instance, 0, tcp_header->source_port,
                 ip_packet->ip_dst, tcp_header->dest_port, ip_packet->ip_src, OUTBOUND_SENT_SYN);
            }

            tcp_header->source_port = mapping->aux_ext;

            /* rewrite source ip as eth2 */
            struct sr_if* iface = sr_get_interface(sr, ext_iface_name);
            ip_packet->ip_src = iface->ip;

            print_hdr_ip((uint8_t*)ip_packet);
            printf("TCP FORWARDING THIS NEW ID: %d\n", ntohs(tcp_header->source_port));

            memcpy((uint8_t*)ip_packet + 4*ip_packet->ip_hl, tcp_header, sizeof(sr_tcp_hdr_t));
        }
    }
}

int nat_translate_from_server(struct sr_instance* sr, uint8_t* packet, sr_ip_hdr_t* ip_packet) {
    sr_tcp_hdr_t* tcp_header = (sr_tcp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
    printf(" INTERFACE --eth1 eth2--- RECIEVED TCP: src port: %d dest_port: %d seq no: %d ack no: %d flags: %d\n",
        ntohs(tcp_header->source_port), ntohs(tcp_header->dest_port), ntohs(tcp_header->seq_number),
        ntohs(tcp_header->ack_number), tcp_header->flags);

    struct sr_nat_mapping* mapping = sr_nat_lookup_external(sr->nat_instance, tcp_header->source_port, nat_mapping_tcp);
    uint32_t target_ip;

    if (mapping) {
        tcp_header->dest_port = mapping->aux_int;
        tcp_header->check_sum = 0;
        target_ip = mapping->ip_int;

        sr_nat_tcp_state state_to_search;
        sr_nat_tcp_state new_state;
        if (tcp_header->flags == (FLAG_SYN + FLAG_ACK)) {
            state_to_search = OUTBOUND_SENT_SYN;
            new_state = ESTABLISHED;
        } else if (tcp_header->flags == (FLAG_ACK)) {
            state_to_search = INBOUND_SYN;
            new_state = ESTABLISHED;
        } else {
            /* if (tcp_header->flags % 2 == 1) */
            state_to_search = ESTABLISHED;
            new_state = LISTEN;
        }

        struct sr_nat_connection* conn = sr_nat_lookup_tcp_connection(sr->nat_instance, mapping->aux_int, 0, 
            mapping->ip_int, mapping->aux_int, ip_packet->ip_src, state_to_search);

        if (conn) {
            if (conn->state == CLOSED) {
                /* unsolicted syn expired after 6 seconds and connection is closed. */
                return 0;
            }
            update_sr_nat_tcp_connection(sr->nat_instance, mapping, ip_packet->ip_src, tcp_header->source_port, new_state);
        } else {
            printf(" ***--------- NO CONNECTION FOUND, DROPPING THIS TCP\n");
            return 0;
        }
    } else if (tcp_header->flags == FLAG_SYN) {
        /* new connection SYN being initiated by server */
            /* setup connection and wait for client to send SYN */
        mapping = sr_nat_insert_mapping(sr->nat_instance, ip_packet->ip_src, tcp_header->source_port, nat_mapping_tcp);
        sr_nat_insert_tcp_connection(sr->nat_instance, ip_packet->ip_src, tcp_header->source_port,
         ip_packet->ip_dst, tcp_header->dest_port, INBOUND_SYN_UNSOLIC);
        return 1;
    }

    /* calc check sums*/
    ip_packet->ip_sum = 0;
    tcp_header->check_sum = 0;
    ip_packet->ip_len = htons(4*ip_packet->ip_hl + sizeof(sr_tcp_hdr_t));
    ip_packet->ip_sum = cksum(ip_packet, 4*ip_packet->ip_hl);

    uint16_t len = ntohs(ip_packet->ip_len);
    tcp_header->check_sum = cksum(tcp_header, len - 4*ip_packet->ip_hl);


    /* construct packet to send */ 
    uint8_t* packet_to_send = malloc(len);
    memcpy(packet_to_send, ip_packet, 4*ip_packet->ip_hl);
    memcpy(packet_to_send + 4*ip_packet->ip_hl, tcp_header, len - 4*ip_packet->ip_hl);

    send_packet(sr, packet_to_send, len, target_ip, ethertype_ip, 0);
    return 1;
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    
    if (len < sizeof(struct sr_ethernet_hdr)) return;
    
    if (ethertype(packet) == ethertype_ip) {
        /* packet is an ip packet */  
        sr_ip_hdr_t* ip_packet =
        (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

        /* check checksum and length */
        if (len < (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)))
            return; 

        uint16_t checksum = ip_packet->ip_sum;
        
        ip_packet->ip_sum = 0;
        uint16_t expected_checksum = cksum(ip_packet, ip_packet->ip_hl*4);
        
        if (checksum != expected_checksum) {
            return;
        }

        print_hdr_ip((uint8_t*)ip_packet);

        if(is_in_interface_lst(sr, ip_packet->ip_dst)) {
            /* reached an eth interface in router, then check if ICMP request */

            if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_icmp)  {
                /* send echo reply */
                make_and_send_icmp_echo(sr, ip_packet);
            } else if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_tcp) {
                
                if (sr->nat_instance) {
                    if (nat_translate_from_server(sr, packet, ip_packet) == 0) {
                        make_and_send_icmp(sr, ip_packet, 3, 3);                        
                    }
                }

            } else {
                /* send icmp port unreachable since its udp or other packet */
                make_and_send_icmp(sr, ip_packet, 3, 3);
            }

        } else {
            /* its not me, must fwd it*/
            
            unsigned int len_packet = ntohs(ip_packet->ip_len);

            /* decrement and check ttl */
            ip_packet->ip_ttl--;
            if (ip_packet->ip_ttl == 0) {
                /* send icmp time exceeded */
                make_and_send_icmp(sr, ip_packet, 11, 0);
                return;
            }

            if (sr->nat_instance) {
                nat_translate_forwarding(sr, packet, ip_packet);                
            }
            
            /* reset checksums if icmp or tcp checksum if they were modified */
            if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_icmp) {
                sr_icmp_t0_hdr_t* icmp_header = (sr_icmp_t0_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
                icmp_header->icmp_sum = 0;
            } else if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_tcp) {
                sr_tcp_hdr_t* tcp_header = (sr_tcp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
                tcp_header->check_sum = 0;
            }

            ip_packet->ip_sum = 0;
            ip_packet->ip_sum = cksum(ip_packet, ip_packet->ip_hl*4);

            /* recalculate icmp and tcp checksum if it was modified */
            if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_icmp)  {
                sr_icmp_t0_hdr_t* icmp_header = (sr_icmp_t0_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
                icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_packet->ip_len) - 4*ip_packet->ip_hl);
            } else if (ip_protocol(packet + sizeof(struct sr_ethernet_hdr)) == (uint8_t)ip_protocol_tcp) {
                sr_tcp_hdr_t* tcp_header = (sr_tcp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr) + 4*ip_packet->ip_hl);
                tcp_header->check_sum = cksum(tcp_header, ntohs(ip_packet->ip_len) - 4*ip_packet->ip_hl);
            }

            uint8_t* ip_packet_copy_to_fwd = malloc(len_packet);
            memcpy(ip_packet_copy_to_fwd, ip_packet, len_packet);

            send_packet(sr, ip_packet_copy_to_fwd, len_packet, ip_packet->ip_dst, ethertype_ip, 1);            
        }

    } else {
        /* packet is an ARP */

        /* meet minimum length */
        if ((sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) > len)
            return;

        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
        
        if (ntohs(arp_header->ar_op) == arp_op_request) {   
            /* got an arp request, send an arp reply */         
            send_arp_reply(sr, arp_header, interface, packet, len);

        } else {
            /* got an arp reply */
            uint32_t ip = arp_header->ar_sip;
            struct sr_arpentry *arp_item = sr_arpcache_lookup(&sr->cache, arp_header->ar_sip);

            if (arp_item == NULL) {
                /* add mapping to cache */
                struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, ip);
            
                if (request != NULL) {
                    /* send out all packets that were waiting on reply to this arp req*/
                    struct sr_packet* sr_pckt = request->packets;
                    sr_ip_hdr_t *ip_header;

                    while (sr_pckt != NULL) {
                        ip_header = (sr_ip_hdr_t*) sr_pckt->buf;
                        send_packet(sr, sr_pckt->buf, sr_pckt->len, ip_header->ip_dst, ethertype_ip, 1);
                        sr_pckt = sr_pckt->next;
                    }
                    sr_arpreq_destroy(&sr->cache, request);
                }

            } else {
                free(arp_item);
            }
        }
    }
}
