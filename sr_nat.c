
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "sr_nat.h"

struct sr_nat_mapping *sr_nat_lookup_external_pointer(struct sr_nat *nat,
                                                      uint16_t aux_ext, sr_nat_mapping_type type);

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */
    
    assert(nat);
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));
    
    /* Initialize timeout thread */
    
    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);
    
    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
    
    nat->mappings = NULL;
    /* Initialize any variables here */
    
    return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */
    
    pthread_mutex_lock(&(nat->lock));
    
    struct sr_nat_mapping *cur = nat->mappings;
    struct sr_nat_mapping *next = NULL;

    while (cur != NULL) {
        next = cur->next;

        struct sr_nat_connection *conns = cur->conns;
        struct sr_nat_connection *conns_next = NULL;
        while (conns) {
            conns_next = conns->next;
            free(conns);
            conns = conns_next;
        }

        free(cur);
        cur = next;
    }

    free(nat);
    
    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
    
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));
        
        time_t curtime = time(NULL);
        
        struct sr_nat_mapping *cur = nat->mappings;
        struct sr_nat_mapping *prev = NULL;

        while (cur != NULL) {
            if ((difftime(curtime, cur->last_updated) > nat->icmp_query_timeout) && cur->type == nat_mapping_icmp) {
                if (prev == NULL) {
                    nat->mappings = cur->next;
                } else {
                    prev->next = cur->next;
                }
                break;
            } else if (cur->type == nat_mapping_tcp) {
                struct sr_nat_connection *conns = cur->conns;
                struct sr_nat_connection *conns_prev = NULL;

                /* clean up connections */
                while (conns) {
                    if ((conns->state == ESTALISHED && (difftime(curtime, conns->last_used) > nat->tcp_established_idle_timeout))
                        || (conns->state == LISTEN && (difftime(curtime, conns->last_used) > nat->tcp_transitionary_idle_timeout))) {
                        
                        if (!conns_prev) {
                            cur->conns = conns->next;
                        } else {
                            conns_prev->next = conns->next;
                        }
                        conns = conns->next;

                    }
                }

                /* clear mapping if no connections left */
                if (!cur->conns) {
                    if (prev == NULL) {
                        nat->mappings = cur->next;
                    } else {
                        prev->next = cur->next;
                    }
                    break;
                }
            }
            prev = cur;
            cur = cur->next;
        }        


        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* find tcp connection associated with the given port */
struct sr_nat_connection *sr_nat_lookup_external_tcp_connection(struct sr_nat *nat,
                                                                uint16_t aux_ext, uint16_t server_port) {
    pthread_mutex_lock(&(nat->lock));


    struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_tcp);
    if (!mapping)
        return NULL;

    struct sr_nat_connection *conns = mapping->conns;
    struct sr_nat_connection *copy_conns = NULL;
    
    while (conns) {
        if (conns->ext_port == server_port) {
            copy_conns = (struct sr_nat_connection*) malloc(sizeof(struct sr_nat_connection));
            memcpy(copy_conns, conns, sizeof(struct sr_nat_connection));
            break;
        }
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy_conns;
}

struct sr_nat_connection *sr_nat_insert_tcp_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                                        uint32_t ext_ip, uint16_t ext_port, sr_nat_tcp_state state) {

    struct sr_nat_connection *conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));

    conn->state = state;
    conn->last_used = time(NULL);
    conn->ext_port = ext_port;
    conn->ext_ip = exp_ip;

    /* insert into linked list */
    struct sr_nat_connection *mapping_conns = mapping->conns;
    conn->next = mapping_conns;

    mapping->conns = conn;

    struct sr_nat_connection *conn_copy = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
    memcpy(conn_copy, conn, sizeof(struct sr_nat_connection));

    return conn;
}

int update_sr_nat_tcp_connection() {

}

struct sr_nat_mapping *sr_nat_lookup_external_pointer(struct sr_nat *nat,
                                                      uint16_t aux_ext, sr_nat_mapping_type type) {
    
    pthread_mutex_lock(&(nat->lock));
    
    struct sr_nat_mapping *cur = nat->mappings;
    struct sr_nat_mapping *copy = NULL;

    while (cur != NULL) {
        if (cur->aux_ext == aux_ext && cur->type == type) {
            cur->last_updated = time(NULL);
            /* copy pointer */
            copy = cur;
            break;
        }
        cur = cur->next;
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type ) {
    
    pthread_mutex_lock(&(nat->lock));
    
    struct sr_nat_mapping *cur = sr_nat_lookup_external_pointer(nat, aux_ext, type);
    struct sr_nat_mapping *copy = NULL;

    copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, cur, sizeof(struct sr_nat_mapping));
    
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

struct sr_nat_mapping *sr_nat_lookup_internal_pointer(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {
    
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *cur = nat->mappings;
    struct sr_nat_mapping *copy = NULL;

    while (cur != NULL) {
        if (cur->aux_int == aux_int && cur->ip_int == ip_int && cur->type == type) {
            cur->last_updated = time(NULL);
            copy = cur;
            break;
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {
    
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *cur = sr_nat_lookup_internal_pointer(nat, ip_int, aux_int, type);
    struct sr_nat_mapping *copy = NULL;

    copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, cur, sizeof(struct sr_nat_mapping));

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {
    
    pthread_mutex_lock(&(nat->lock));
    
    struct sr_nat_mapping* mapping = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->aux_ext = htons(rand() % 64511 + 1024);
    printf("Made random aux_ext: %d\n", ntohs(mapping->aux_ext));
    mapping->last_updated = time(NULL);
    mapping->type = type;

    mapping->next = nat->mappings;
    nat->mappings = mapping;
    
    struct sr_nat_mapping* mapping_copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));
    
    
    pthread_mutex_unlock(&(nat->lock));
    return mapping_copy;
}
