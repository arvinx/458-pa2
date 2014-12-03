
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

/* TCP FLAGS */
#define FLAG_FIN    1
#define FLAG_SYN    2
#define FLAG_PUSH   8
#define FLAG_ACK    16

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  LISTEN,
  OUTBOUND_SENT_SYN,
  INBOUND_SYN,
  INBOUND_SYN_UNSOLIC,
  CLOSED,
  ESTABLISHED
} sr_nat_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  sr_nat_tcp_state state;
  time_t last_used;
  uint32_t ext_ip; /* server ip */
  uint16_t ext_port; /* server port */
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;

  /* optional args */
  int icmp_query_timeout;
  int tcp_established_idle_timeout;
  int tcp_transitionary_idle_timeout;

};


int sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


struct sr_nat_connection *sr_nat_lookup_tcp_connection(struct sr_nat *nat,
  uint16_t aux_ext, uint16_t aux_int, uint32_t dst_ip, uint16_t dst_port, uint32_t src_ip, sr_nat_tcp_state state);

struct sr_nat_connection *sr_nat_insert_tcp_connection(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ext_ip, uint16_t ext_port, sr_nat_tcp_state state);

int update_sr_nat_tcp_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping,
  uint32_t ext_ip, uint16_t ext_port, sr_nat_tcp_state new_state);

#endif