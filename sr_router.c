#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* Helper function declarations */
void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_tcp_udp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
sr_ethernet_hdr_t *get_ethernet_header(uint8_t *packet);
sr_arp_hdr_t *get_arp_header(uint8_t *packet);
sr_ip_hdr_t *get_ip_header(uint8_t *packet);
sr_icmp_hdr_t *get_icmp_header(uint8_t *packet);
void create_ethernet_header(uint8_t *packet, uint8_t *src_mac, uint8_t *dest_mac, uint16_t eth_type);
void create_arp_header(uint8_t *packet, uint16_t op_code, uint8_t *src_mac, sr_arp_hdr_t *request_arp_hdr);
struct sr_if *sr_get_router_interface(struct sr_instance *sr, uint32_t ip);
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip);
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip);
void handle_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_tcp_udp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
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

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Packet length less than minimum ethernet header length, dropping this packet\n");
    return;
  }

  uint16_t type = ethertype(packet);

  if (type == ethertype_ip) {
    handle_ip_packet(sr, packet, len, interface);
  }
  else if (type == ethertype_arp) {
    /* will check for ARP request or reply in the helper */
    handle_arp_packet(sr, packet, len, interface);
  }
  else{
    /* Unknown Ethernet frame type, should just drop silently according to Piazza post */
    fprintf(stderr, "Unknown Ethernet frame type, dropping this packet\n");
    return;
  }

  return;

} /* end sr_ForwardPacket */



/*/////////////////////////////////////////////////////Two Main Helpers Start/////////////////////////////////////////////////////////////////*/

/* Handle IP packet */
void handle_ip_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  assert(sr);
  assert(packet);
  assert(interface);

  sr_ethernet_hdr_t *eth_hdr = get_ethernet_header(packet);
  if (!eth_hdr) {
      fprintf(stderr, "Failure in handle_ip_packet() after getting ethernet header, exiting handle_ip_packet()\n");
      return;
  }

  sr_ip_hdr_t *ip_hdr = get_ip_header(packet);
  if (!ip_hdr) {
      fprintf(stderr, "Failure in handle_ip_packet() after getting ip header, exiting handle_ip_packet()\n");
      return;
  }

  /* Validate IP packet */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "Packet too short for IP header, dropping packet\n");
      return;
  }
  
  if (ip_hdr->ip_v != 4) {
      fprintf(stderr, "Not IPv4 packet, dropping packet\n");
      return;
  }
  
  if (ip_hdr->ip_hl < 5) {
      fprintf(stderr, "Invalid IP header length, dropping packet\n");
      return;
  }
  
  if (ntohs(ip_hdr->ip_len) < sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "IP length too small, dropping packet\n");
      return;
  }
  
  /* Check the checksum */
  uint16_t received_checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t calculated_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (received_checksum != calculated_checksum) {
      fprintf(stderr, "IP checksum mismatch, dropping packet\n");
      ip_hdr->ip_sum = received_checksum; /* Restore for error reporting */
      return;
  }
  ip_hdr->ip_sum = received_checksum; /* Restore original checksum */

  struct sr_if *connected_interface = sr_get_interface(sr, interface);
  if (!connected_interface){
      fprintf(stderr, "Failure in handle_ip_packet() after getting interface, our router doesn't have this interface. Exiting handle_ip_packet()\n");
      return;
  }

  struct sr_arpcache *arp_cache = &(sr->cache);
  if (!arp_cache) {
      fprintf(stderr, "Failure in handle_ip_packet() after getting arp cache, exiting handle_ip_packet()\n");
      return;
  }

  struct sr_if *destination_interface = sr_get_router_interface(sr, ip_hdr->ip_dst);

  /* check TTL */
  if(ip_hdr->ip_ttl <= 1){
    /* send ICMP time exceeded to source addr */
    sr_send_icmp_packet(sr, packet, len, interface, 11, 0);
    return;
  }

  /* Is it sent to me? */
  if (ip_hdr->ip_dst == connected_interface->ip) {
    /* Distinguish between ICMP echo request and TCP/UDP */
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      /* Handle ICMP packet */
      handle_icmp_packet(sr, packet, len, interface);
    } else {
      /* Handle TCP/UDP packet */
      handle_tcp_udp_packet(sr, packet, len, interface);
    }
  }
  else{
    /* Should be forwarding case, perform Longest Prefix Match */
    struct sr_rt *routing_entry = longest_prefix_match(sr, ip_hdr->ip_dst);

    if (!routing_entry) {
      /* No matching route found, send ICMP destination unreachable */
      sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
      return;
    }

    /* Validate that the routing entry interface exists */
    struct sr_if *out_interface = sr_get_interface(sr, routing_entry->interface);
    if (!out_interface) {
      fprintf(stderr, "Routing entry references non-existent interface %s, sending ICMP unreachable\n", routing_entry->interface);
      sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
      return;
    }
    
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(arp_cache, routing_entry->gw.s_addr);
    if (arp_entry) {
      ip_hdr->ip_ttl -= 1;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, routing_entry->interface);
      free(arp_entry);
      return;
    }
    else{
      ip_hdr->ip_ttl -= 1;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      struct sr_arpreq *arp_request = sr_arpcache_queuereq(arp_cache, routing_entry->gw.s_addr, packet, len, routing_entry->interface);
      if (arp_request) {
        handle_arpreq(sr, arp_request);
      }
      return;
    }
    return;
  }
}

/* Handle ARP packet */
void handle_arp_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  assert(sr);
  assert(packet);
  assert(interface);

  sr_ethernet_hdr_t *eth_hdr = get_ethernet_header(packet);
  if (!eth_hdr) {
      fprintf(stderr, "Failure in handle_arp_packet() after getting ethernet header, exiting handle_arp_packet()\n");
      return;
  }

  sr_arp_hdr_t *arp_hdr = get_arp_header(packet);
  if (!arp_hdr) {
      fprintf(stderr, "Failure in handle_arp_packet() after getting arp header, exiting handle_arp_packet()\n");
      return;
  }

  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))){
      fprintf(stderr, "Packet length less than minimum ARP header length, exiting handle_arp_packet()\n");
      return;
  }
  
  /* Validate ARP packet structure */
  if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
      fprintf(stderr, "ARP hardware type not Ethernet, dropping packet\n");
      return;
  }
  
  if (ntohs(arp_hdr->ar_pro) != ethertype_ip) {
      fprintf(stderr, "ARP protocol type not IP, dropping packet\n");
      return;
  }
  
  if (arp_hdr->ar_hln != ETHER_ADDR_LEN || arp_hdr->ar_pln != 4) {
      fprintf(stderr, "Invalid ARP address lengths, dropping packet\n");
      return;
  }

  struct sr_if *connected_interface= sr_get_interface(sr, interface);
  if (!connected_interface){
      fprintf(stderr, "Failure in handle_arp_packet() after getting interface, our router doesn't have this interface. Exiting handle_arp_packet()\n");
      return;
  }

  /* Now, after standard checks, we need to see if this is request or reply */
  /* We need to check the op code*/
  if (ntohs(arp_hdr->ar_op) == arp_op_request){
    /* Check if the target IP is one of our router's interfaces */
    if (arp_hdr->ar_tip != connected_interface->ip) {
      /* Not for us, drop silently */
      return;
    }
    
    /* We need to craft an ARP reply packet */
    uint8_t *arp_reply_header = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    if (!arp_reply_header) {
        fprintf(stderr, "Failed to allocate memory for ARP reply header, exiting handle_arp_packet()\n");
        return;
    }

    create_ethernet_header(arp_reply_header, connected_interface->addr, eth_hdr->ether_shost, ethertype_arp);
    create_arp_header(arp_reply_header, arp_op_reply, connected_interface->addr, arp_hdr);
    sr_send_packet(sr, arp_reply_header, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

    free(arp_reply_header);

  }
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
    /* Check if the target IP is one of our router's interfaces */
    if (arp_hdr->ar_tip != connected_interface->ip) {
      /* Not for us, drop silently */
      return;
    }
    
    /* We need to update our ARP cache */
    struct sr_arpcache *arp_cache = &(sr->cache);

    struct sr_arpreq *arp_request = sr_arpcache_insert(arp_cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if(arp_request){
      fprintf(stderr, "There are packets waiting on this ARP request, sending them now\n");

      struct sr_packet *packet_waiting = arp_request->packets;
      while(packet_waiting != NULL){
        /* Update the ethernet header of the packet */
        sr_ethernet_hdr_t *waiting_eth_hdr = get_ethernet_header(packet_waiting->buf);
        if (!waiting_eth_hdr) {
            fprintf(stderr, "Failure in handle_arp_packet() after getting ethernet header of waiting packet, skipping this packet\n");
            packet_waiting = packet_waiting->next;
            continue;
        }

        struct sr_if *outgoing_interface = sr_get_interface(sr, packet_waiting->iface);
        if (!outgoing_interface){
            fprintf(stderr, "Failure in handle_arp_packet() after getting interface of waiting packet, skipping this packet\n");
            packet_waiting = packet_waiting->next;
            continue;
        }
        /* update mac sender address */
        create_ethernet_header(packet_waiting->buf, outgoing_interface->addr, arp_hdr->ar_sha, ethertype_ip);
        sr_send_packet(sr, packet_waiting->buf, packet_waiting->len, outgoing_interface->name);
        packet_waiting = packet_waiting->next;
    }
    sr_arpreq_destroy(arp_cache, arp_request);
    }
  }
}
/*/////////////////////////////////////////////////////Two Main Helpers End/////////////////////////////////////////////////////////////////*/





/*/////////////////////////////////////////////////////Small Helper Functions Start/////////////////////////////////////////////////////////////////*/
/* Get ethernet header */
sr_ethernet_hdr_t *get_ethernet_header(uint8_t *packet) {
    assert(packet);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    if (!eth_hdr) {
        fprintf(stderr, "Failure in get_ethernet_header(), returning NULL\n");
        return NULL;
    } 

    return eth_hdr;
}

sr_ip_hdr_t *get_ip_header(uint8_t *packet) {
    assert(packet);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));
    if (!ip_hdr) {
        fprintf(stderr, "Failure in get_ip_header(), returning NULL\n");
        return NULL;
    } 
    return ip_hdr;
}

sr_icmp_hdr_t *get_icmp_header(uint8_t *packet) {
    assert(packet);

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    if (!icmp_hdr) {
        fprintf(stderr, "Failure in get_icmp_header(), returning NULL\n");
        return NULL;
    } 
    return icmp_hdr;
}


/* Get arp header */
sr_arp_hdr_t * get_arp_header(uint8_t *packet) {
    assert(packet);

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));
    if (!arp_hdr) {
        fprintf(stderr, "Failure in get_arp_header(), returning NULL\n");
        return NULL;
    } 
    return arp_hdr;
}

/* Create Ethernet header */
void create_ethernet_header(uint8_t *packet, uint8_t *src_mac, uint8_t *dest_mac, uint16_t eth_type) {
    assert(packet);
    assert(src_mac);
    assert(dest_mac);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    if (!eth_hdr) {
        fprintf(stderr, "Failure in create_ethernet_header(), exiting function\n");
        return;
    } 

    /* we want to swap source and destination MAC addresses */
    memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(eth_type);
    
    return;
}

void create_arp_header(uint8_t *packet, uint16_t op_code, uint8_t *src_mac, sr_arp_hdr_t *request_arp_hdr) {
    assert(packet);
    assert(src_mac);
    assert(request_arp_hdr);

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));
    if (!arp_hdr) {
        fprintf(stderr, "Failure in create_arp_header(), exiting function\n");
        return;
    } 

    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4; /* IPv4 address length */
    arp_hdr->ar_op = htons(op_code); /* ARP request or reply */

    memcpy(arp_hdr->ar_sha, src_mac, ETHER_ADDR_LEN); /* our MAC address */
    arp_hdr->ar_sip = request_arp_hdr->ar_tip; /* our IP address is the target IP of the request */

    memcpy(arp_hdr->ar_tha, request_arp_hdr->ar_sha, ETHER_ADDR_LEN); /* target hardware address is sender hardware address of the request */
    arp_hdr->ar_tip = request_arp_hdr->ar_sip; /* target IP address is sender IP address of the request */

    return;
}

struct sr_if *sr_get_router_interface(struct sr_instance *sr, uint32_t ip) {
  assert(sr);
  assert(ip);

  struct sr_if *interface = NULL;
  for (interface = sr->if_list; interface != NULL; interface = interface->next) {
    if (interface->ip == ip) {
      return interface;
    }
  }

  return NULL;
}


/* Stub implementations for unimplemented functions */
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip) {
  assert(sr);
  assert(ip);  

  struct sr_rt *routing_table = sr->routing_table;
  struct sr_rt *longest_match = NULL;

  uint32_t max_prefix_len = 0;

  while(routing_table != NULL){
    if((ip & routing_table->mask.s_addr) == (routing_table->dest.s_addr & routing_table->mask.s_addr)){
      if(routing_table->mask.s_addr > max_prefix_len){
        max_prefix_len = routing_table->mask.s_addr;
        longest_match = routing_table;
      }
    }
    routing_table = routing_table->next;
  }

  return longest_match;
}

void handle_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    sr_ip_hdr_t *ip_hdr = get_ip_header(packet);
    if (!ip_hdr) {
        fprintf(stderr, "Failure in handle_icmp_packet() after getting ip header, exiting handle_icmp_packet()\n");
        return; 
    }

    if (ip_hdr->ip_p == ip_protocol_icmp) {
        sr_icmp_hdr_t *icmp_hdr = get_icmp_header(packet);
        if (!icmp_hdr) {
            fprintf(stderr, "Failure in handle_icmp_packet() after getting icmp header, exiting handle_icmp_packet()\n");
            return;
        }

        if (icmp_hdr->icmp_type == 8) { /* ICMP echo request */
            send_icmp_echo_reply(sr, packet, len, interface);
            return;
        }
    }
}

void handle_tcp_udp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Send ICMP port unreachable */
    sr_send_icmp_packet(sr, packet, len, interface, 3, 3); /* type 3: destination unreachable, code 3: port unreachable */
    return;
}

/* Send ICMP echo reply */
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    assert(sr);
    assert(packet);
    assert(interface);
    
    /* Create echo reply packet */
    uint8_t *reply_packet = (uint8_t *)malloc(len);
    if (!reply_packet) {
        fprintf(stderr, "Failed to allocate memory for echo reply\n");
        return;
    }
    
    /* Copy original packet */
    memcpy(reply_packet, packet, len);
    
    /* Get headers */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* Swap Ethernet addresses */
    uint8_t temp_mac[ETHER_ADDR_LEN];
    memcpy(temp_mac, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, temp_mac, ETHER_ADDR_LEN);
    
    /* Swap IP addresses */
    uint32_t temp_ip = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp_ip;
    
    /* Update ICMP header */
    icmp_hdr->icmp_type = 0; /* Echo reply */
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
    
    /* Update IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    /* Send using sr_send_packet */
    sr_send_packet(sr, reply_packet, len, interface);
    
    free(reply_packet);
}
/*/////////////////////////////////////////////////////Small Helper Functions End/////////////////////////////////////////////////////////////////*/