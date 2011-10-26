/* Copyright (c) 2007 by Errata Security */
#ifndef __PROTOS_H
#define __PROTOS_H

struct Seaper;
struct NetFrame;

void process_wifi_frame(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ethernet_frame(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_802_1x_auth(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_cisco00000c(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_arp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ip(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ipv6(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_udp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_tcp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_igmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_gre(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_icmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_icmpv6(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_pptp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_cups(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_dns(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_dhcp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_netbios_dgm(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_smb_dgm(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ssdp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_callwave_iam(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_snmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_upnp_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_srvloc(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_isakmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ldap(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_http(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);


void process_simple_msnms_server_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_msnms_client_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_simple_pop3_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_pop3_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_simple_smtp_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_smtp_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length);

#endif /*__PROTOS_H*/

