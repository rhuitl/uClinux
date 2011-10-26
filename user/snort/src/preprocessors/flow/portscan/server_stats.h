#ifndef _SERVER_STATS_H
#define _SERVER_STATS_H

#include <stdio.h>

#include "flowps.h"
#include "sfxhash.h"
#include "ipobj.h"

#define SERVER_STATS_MAX_HITCOUNT 0xFFFFFFFF

void server_stats(SERVER_STATS *ssp, int dumpall);
void server_stats_dump(SERVER_STATS *ssp);

int server_stats_init(SERVER_STATS *ssp, IPSET *watchnet, unsigned int rows, int memcap);
int server_stats_destroy(SERVER_STATS *ssp);

u_int32_t server_stats_hitcount_ipv4(SERVER_STATS *ssp,
                                    u_int8_t ip_proto,
                                    u_int32_t address,
                                    u_int16_t port);

int server_stats_add_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address,
                          u_int16_t port, u_int32_t *retcount);

int server_stats_remove_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address, u_int16_t port);

int server_stats_save(SERVER_STATS *ssp, char *filename);

int server_stats_row_count(SERVER_STATS *sbp);
int server_stats_memcap(SERVER_STATS *sbp);
int server_stats_overhead_bytes(SERVER_STATS *sbp);
int server_stats_contains(SERVER_STATS *ssp, u_int32_t address);
#endif /* _SERVER_STATS_H */
