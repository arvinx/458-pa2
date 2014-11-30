
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "sr_nat.h"


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
            }
            prev = cur;
            cur = cur->next;
        }        


        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type ) {
    
    pthread_mutex_lock(&(nat->lock));
    
    struct sr_nat_mapping *cur = nat->mappings;
    struct sr_nat_mapping *copy = NULL;

    while (cur != NULL) {
        if (cur->aux_ext == aux_ext && cur->type == type) {
            cur->last_updated = time(NULL);
            copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, cur, sizeof(struct sr_nat_mapping));
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

    struct sr_nat_mapping *cur = nat->mappings;
    struct sr_nat_mapping *copy = NULL;

    while (cur != NULL) {
        if (cur->aux_int == aux_int && cur->ip_int == ip_int && cur->type == type) {
            cur->last_updated = time(NULL);
            copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, cur, sizeof(struct sr_nat_mapping));
            break;
        }
        cur = cur->next;
    }

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
    
    if (type == nat_mapping_icmp) {
        mapping->ip_int = ip_int;
        mapping->aux_int = aux_int;
        mapping->aux_ext = htons(rand() % 64511 + 1024);
        printf("Made random aux_ext: %d\n", ntohs(mapping->aux_ext));
        mapping->last_updated = time(NULL);
        mapping->type = nat_mapping_icmp;
    } else {
        
    }
    
    mapping->next = nat->mappings;
    nat->mappings = mapping;
    
    struct sr_nat_mapping* mapping_copy = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));
    memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));
    
    
    pthread_mutex_unlock(&(nat->lock));
    return mapping_copy;
}
