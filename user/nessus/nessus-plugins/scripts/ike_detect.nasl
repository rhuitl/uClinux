#
# (C) Tenable Network Security
#
# script audited and subsequently patched thanks to submission by Bert Salaets
#
# VPN Vendor signatures were generated from the ike-scan project
# written by Roy Hills and distributed by NTA Monitor.
# See also : http://www.nta-monitor.com/ike-scan/

 desc["english"] =  "
Synopsis :

A VPN server is listening on the remote port.

Description :

The remote host seems to be enabled to do Internet Key
Exchange (IKE).  This is typically indicative of a VPN server.
VPN servers are used to connect remote hosts into internal
resources.  

Make sure that the use of this VPN endpoint is done in accordance with 
your corporate security policy.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";

if(description) {
 script_id(11935);
 script_version("$Revision: 1.15 $");

 name["english"] = "IPSEC IKE detection";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "IPSEC IKE detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
  script_family(english:"Service detection");
  script_require_keys("Settings/ThoroughTests");

 exit(0);
}

#
# The script code starts here
#
include('misc_func.inc');
include('global_settings.inc');


function calc_data() {
    T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3
+ T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 +  T_AC6 + T_ALEN + T_AV6;

   for (MU=2; MU < TRANSFORM_MAX; MU++) {

    TPAY[MU] = T_NP + T_RES + T_PLEN + raw_string(MU) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;

}

TPAY[MU] = raw_string(0x00) + T_RES + T_PLEN + raw_string(MU) +  T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;
 

    tmp =  (MU * T_PAY_SZ) + strlen(IC) + strlen(RC) + strlen(NP) + strlen(MV) + strlen(ET) + strlen(IF) + strlen(MI) + 4;
    
    tmp = tmp + SA_HEADER_SZ + PROP_HEADER_SZ;               # sizeof SA_HEADER + PROP_HEADER
    myplen = tmp - 28;
    myp_plen = myplen - 12;

    len4 = tmp / 0xFFFFFF;
    len3 = tmp / 0xFFFF;
    len2 = tmp / 0xFF;
    len1 = tmp % 256;
    LEN=raw_string(len4,len3,len2,len1);

    len2 = myplen / 0xFF;
    len1 = myplen % 256;
    PLEN=raw_string(len2, len1);

    len2 = myp_plen / 0xFF;
    len1 = myp_plen % 256;
    P_PLEN=raw_string(len2, len1);   

    SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;

    PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + T_NUM_TOT;

    ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;

    blap = ISAKMP_HEADER + SA_HEADER + PROP_HEADER + T_PAY1;
    for (MU=2; MU <= TRANSFORM_MAX; MU++) {    
        blap = blap + TPAY[MU];
    }

    return(blap);
}





srcaddr = this_host();
dstaddr = get_host_ip();
port = 500;
srcport = rand() % 65535;

if(!get_udp_port_state(port))
	exit(0);



#------ISAKMP header-----#

IC = raw_string (0xFF, 0x00, 0xFE, 0x01, 0xFD, 0x02, 0xFC, 0x03);    #8 byte Initiator cookie
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


ET = raw_string (0x02);                                              # Exchange type = 4 = AGGRESSIVE
                                                                     # 0 = NONE / 1 = BASE / 2 = Identity protection
                                                                     # 3 = Authentication only  / 5 = Informational
                                                                     # 6-31 = FUTURE USE / 32-239 = DOI use
                                                                     # 240-255 = Private use

IF = raw_string (0x00);
MI = raw_string(0x00,0x00,0x00,0x00);                                # Message ID
#LEN = raw_string (0x00,0x00,0x01,0x7b);                              # Length = total length of UDP data field


#ISAKMP_HEADER = IC + RC + NP + MV + ET + IF + MI + LEN;
ISAKMP_HEADER_SZ = 28;





# ----- Security Association ---------#

SA_NP = raw_string(0x00);                                            # Security Association next payload = key exchange
RES = raw_string(0x00);                                              # reserved
PLEN = raw_string(0x00,0x80);                                        # Security association payload length = LEN - 28
                                                                     # total len of all payloads (through last TP) + 12
DOI = raw_string(0x00,0x00,0x00,0x01);                               # DOI = generic ISAKMP Security Association
SIT = raw_string(0x00,0x00,0x00,0x01);                               # Situation

SA_HEADER = SA_NP + RES + PLEN + DOI + SIT;
SA_HEADER_SZ = 12;






# ------Proposal --------------------#

P_NP = raw_string(0x00);                                             # Proposal next payload = 0 (last proposal payload)
P_RES = raw_string(0x00);                                            # reserved
P_PLEN = raw_string(0x00,0x74);                                      # Proposal payload length = LEN - 40 
                                                                     # payloads through last TP
P_NUM = raw_string(0x01);                                            # proposal number
PID = raw_string(0x01);                                              # protocol ID = 1 = proto_isakmp
SPI_SZ = raw_string(0x00);                                           # SPI size
T_NUM_TOT = raw_string(0x08);                                            # number of transforms

PROP_HEADER = P_NP + P_RES + P_PLEN + P_NUM + PID + SPI_SZ + T_NUM_TOT;
PROP_HEADER_SZ = 8;






# -----Transform Payload ------------#
T_NP = raw_string(0x03);                                             # transform next payload = 3 = more transforms
T_RES = raw_string(0x00);                                            # reserved
T_PLEN = raw_string(0x00,0x24);                                      # payload length --  36 bytes per transform
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
T_AC3 = raw_string(0x03);                                            # attribute type/class = 4 = group description basic
T_AV3 = raw_string(0x00,0x01);                                       # attribute value = 2 = alternate 1024 bit MODP group
T_FLAGS4 = raw_string(0x80);
T_AC4 = raw_string(0x04);                                            # attribute type/class = 3 = basic authentication
T_AV4 = raw_string(0x00,0x02);                                       # attribute value = 65001 = for private use
T_FLAGS5 = raw_string(0x80);
T_AC5 = raw_string(0x0b);                                            # attribute type/class = 11 = basic life type
T_AV5 = raw_string(0x00,0x01);                                       # attribute value = 1 = life duration in seconds
T_FLAGS6 = raw_string(0x00);
T_AC6 = raw_string(0x0c);                                            # attribute type/class = 12 = variable life duration
T_ALEN = raw_string(0x00,0x04);                                      # attribute length = 4 bytes
T_AV6 = raw_string(0x00,0x20,0xC4,0x9B);                             # attribute value

T_PAY_SZ = 36;

T_PAY1 = T_NP + T_RES + T_PLEN + T_NUM + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 +
T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;







# -----Transform Payloads 2 and up -----------#
# nothing changes except transform number .... and "Next payload" (on last payload)

TRANSFORM_MAX = 8;

for (TPAYRRAY=2; TPAYRRAY < TRANSFORM_MAX; TPAYRRAY++) {

    TPAY[TPAYRRAY] = T_NP + T_RES + T_PLEN + raw_string(TPAYRRAY) + T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6; 
}

TPAY[TPAYRRAY] = raw_string(0x00) + T_RES + T_PLEN + raw_string(TPAYRRAY) +  T_ID + T_RES2 + T_FLAGS + T_AC + T_AV + T_FLAGS2 + T_AC2 + T_AV2 + T_FLAGS3 + T_AC3 + T_AV3 + T_FLAGS4 + T_AC4 + T_AV4 + T_FLAGS5 + T_AC5 + T_AV5 + T_FLAGS6 + T_AC6 + T_ALEN + T_AV6;





#--------end Proposal Payload ------------------------#

#--------end Security Association Payload-------------#


# Signatures are from the ike-scan project.  Props to Roy Hills (http://www.nta-monitor.com/ike-scan/)
sig[0] = hex2raw(s:"ad2c0dd0b9c32083ccba25b8861ec455");
vendor[0] = "A GSS-API Authentication Method for IKE    ";
sig[1] = hex2raw(s:"b46d8914f3aaa3f2fedeb7c7db2943ca");
vendor[1] = "A GSS-API Authentication Method for IKE\n  ";
sig[2] = hex2raw(s:"bdb41038a7ec5e5534dd004d0f91f927");
vendor[2] = "Cisco IOS";
sig[3] = hex2raw(s:"12f5f28c457168a9702d9fe274cc0100");
vendor[3] = "Cisco Unity";
sig[4] = hex2raw(s:"afcad71368a1f1c96b8696fc7757....");
vendor[4] = "Dead Peer Detection";
sig[5] = hex2raw(s:"6a7434c19d7e36348090a02334c9c805");
vendor[5] = "draft-huttunen-ipsec-esp-in-udp-00.txt";
sig[6] = hex2raw(s:"4485152d18b6bbcd0be8a8469579ddcc");
vendor[6] = "draft-ietf-ipsec-nat-t-ike-00";
sig[7] = hex2raw(s:"16f6ca16e4a4066d83821a0f0aeaa862");
vendor[7] = "draft-ietf-ipsec-nat-t-ike-01";
sig[8] = hex2raw(s:"cd60464335df21f87cfdb2fc68b6a448");
vendor[8] = "draft-ietf-ipsec-nat-t-ike-02";
sig[9] = hex2raw(s:"90cb80913ebb696e086381b5ec427b1f");
vendor[9] = "draft-ietf-ipsec-nat-t-ike-02";
sig[10] = hex2raw(s:"7d9419a65310ca6f2c179d9215529d56");
vendor[10] = "draft-ietf-ipsec-nat-t-ike-03";
sig[11] = hex2raw(s:"27bab5dc01ea0760ea4e3190ac27c0d0");
vendor[11] = "draft-stenberg-ipsec-nat-traversal-01";
sig[12] = hex2raw(s:"6105c422e76847e43f9684801292aecd");
vendor[12] = "draft-stenberg-ipsec-nat-traversal-02";
sig[13] = hex2raw(s:"50760f624c63e5c53eea386c685ca083");
vendor[13] = "ESPThruNAT";
sig[14] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000020000000000000000");
vendor[14] = "Firewall-1 4.1 Base";
sig[15] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000030000000000000000");
vendor[15] = "Firewall-1 4.1 SP1";
sig[16] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f0000000100000fa20000000000000000");
vendor[16] = "Firewall-1 4.1 SP2-SP6";
sig[17] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138c0000000000000000");
vendor[17] = "Firewall-1 NG AI R54";
sig[18] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d0000000000000000");
vendor[18] = "Firewall-1 NG AI R55";
sig[19] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013880000000000000000");
vendor[19] = "Firewall-1 NG Base";
sig[20] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013890000000000000000");
vendor[20] = "Firewall-1 NG FP1";
sig[21] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138a0000000000000000");
vendor[21] = "Firewall-1 NG FP2";
sig[22] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138b0000000000000000");
vendor[22] = "Firewall-1 NG FP3";
sig[23] = hex2raw(s:"f4ed19e0c114eb516faaac0ee37daf2807b4381f");
vendor[23] = "Firewall-1 Unknown Vsn";
sig[24] = hex2raw(s:"621b04bb09882ac1e15935fefa24aeee");
vendor[24] = "GSSAPI";
sig[25] = hex2raw(s:"4865617274426561745f4e6f74696679");
vendor[25] = "Heartbeat Notify";
sig[26] = hex2raw(s:"4048b7d56ebce88525e7de7f00d6c2d3");
vendor[26] = "IKE Fragmentation";
sig[27] = hex2raw(s:"7003cbc1097dbe9c2600ba6983bc8b35");
vendor[27] = "KAME/racoon";
sig[28] = hex2raw(s:"1e2b516905991c7d7c96fcbfb587e461");
vendor[28] = "MS NT5 ISAKMPOAKLEY";
sig[29] = hex2raw(s:"9b096d9ac3275a7d6fe8b91c583111b09efed1a0");
vendor[29] = "Netscreen";
sig[30] = hex2raw(s:"4f70656e5047503130313731");
vendor[30] = "OpenPGP";
sig[31] = hex2raw(s:"da8e9378");
vendor[31] = "Safenet or Watchguard";
sig[32] = hex2raw(s:"47bbe7c993f1fc13b4e6d0db565c68e5");
vendor[32] = "SafeNet SoftRemote";
sig[33] = hex2raw(s:"fbf47614984031fa8e3bb6198089b223");
vendor[33] = "SSH IPSEC Express 1.1.0";
sig[34] = hex2raw(s:"1952dc91ac20f646fb01cf42a33aee30");
vendor[34] = "SSH IPSEC Express 1.1.1";
sig[35] = hex2raw(s:"e8bffa643e5c8f2cd10fda7370b6ebe5");
vendor[35] = "SSH IPSEC Express 1.1.2";
sig[36] = hex2raw(s:"c1111b2dee8cbc3d620573ec57aab9cb");
vendor[36] = "SSH IPSEC Express 1.2.1";
sig[37] = hex2raw(s:"09ec27bfbc09c75823cfecbffe565a2e");
vendor[37] = "SSH IPSEC Express 1.2.2";
sig[38] = hex2raw(s:"7f21a596e4e318f0b2f4944c2384cb84");
vendor[38] = "SSH IPSEC Express 2.0.0";
sig[39] = hex2raw(s:"2836d1fd2807bc9e5ae30786320451ec");
vendor[39] = "SSH IPSEC Express 2.1.0";
sig[40] = hex2raw(s:"a68de756a9c5229bae66498040951ad5");
vendor[40] = "SSH IPSEC Express 2.1.1";
sig[41] = hex2raw(s:"3f2372867e237c1cd8250a75559cae20");
vendor[41] = "SSH IPSEC Express 2.1.2";
sig[42] = hex2raw(s:"0e58d5774df602007d0b02443660f7eb");
vendor[42] = "SSH IPSEC Express 3.0.0";
sig[43] = hex2raw(s:"f5ce31ebc210f44350cf71265b57380f");
vendor[43] = "SSH IPSEC Express 3.0.1";
sig[44] = hex2raw(s:"f64260af2e2742daddd56987068a99a0");
vendor[44] = "SSH IPSEC Express 4.0.0";
sig[45] = hex2raw(s:"7a54d3bdb3b1e6d923892064be2d981c");
vendor[45] = "SSH IPSEC Express 4.0.1";
sig[46] = hex2raw(s:"9aa1f3b43472a45d5f506aeb260cf214");
vendor[46] = "SSH IPSEC Express 4.1.0";
sig[47] = hex2raw(s:"6880c7d026099114e486c55430e7abee");
vendor[47] = "SSH IPSEC Express 4.2.0";
sig[48] = hex2raw(s:"054182a07c7ae206f9d2cf9d2432c482");
vendor[48] = "SSH Sentinel";
sig[49] = hex2raw(s:"b91623e693ca18a54c6a2778552305e8");
vendor[49] = "SSH Sentinel 1.1";
sig[50] = hex2raw(s:"5430888de01a31a6fa8f60224e449958");
vendor[50] = "SSH Sentinel 1.2";
sig[51] = hex2raw(s:"7ee5cb85f71ce259c94a5c731ee4e752");
vendor[51] = "SSH Sentinel 1.3";
sig[52] = hex2raw(s:"eb4b0d96276b4e220ad16221a7b2a5e6");
vendor[52] = "SSH Sentinel 1.4.1";
sig[53] = hex2raw(s:"63d9a1a7009491b5a0a6fdeb2a8284f0");
vendor[53] = "SSH Sentinel 1.4";
sig[54] = hex2raw(s:"c40fee00d5d39ddb1fc762e09b7cfea7");
vendor[54] = "Testing NAT-T RFC";
sig[55] = hex2raw(s:"54494d4553544550");
vendor[55] = "Timestep";
sig[56] = hex2raw(s:"975b7816f69789600dda89040576e0db");
vendor[56] = "Unknown VPN Vendor";
sig[57] = hex2raw(s:"1f07f70eaa6514d3b0fa96542a");
vendor[57] = "Unknown VPN Vendor";
sig[58] = hex2raw(s:"edea53a3c15d45cafb11e59ea68db2aa99c1470e0000000400000303");
vendor[58] = "Unknown VPN Vendor";
sig[59] = hex2raw(s:"bedc86dabf0ab7973870b5e6c4b87d3ee824de310000001000000401");
vendor[59] = "Unknown VPN Vendor";
sig[60] = hex2raw(s:"ac5078c25cabb9523979978e76a3d0d2426bc9260000000400000401");
vendor[60] = "Unknown VPN Vendor";
sig[61] = hex2raw(s:"69b761a173cc1471dc4547d2a5e94812");
vendor[61] = "Unknown VPN Vendor";
sig[62] = hex2raw(s:"4c5647362e303a627269636b3a362e302e353732");
vendor[62] = "Unknown VPN Vendor";
sig[63] = hex2raw(s:"3499691eb82f9eaefed378f5503671debd0663b4000000040000023c");
vendor[63] = "Unknown VPN Vendor";
sig[64] = hex2raw(s:"e23ae9f51a46876ff93d89ba725d649d");
vendor[64] = "Unknown Cisco VPN";
sig[65] = hex2raw(s:"1e2b516905991c7d7c96fcbfb587e46100000002");
vendor[65] = "Windows-2000";
sig[66] = hex2raw(s:"1e2b516905991c7d7c96fcbfb587e461000000040d000014");
vendor[66] = "Windows-2003";
sig[67] = hex2raw(s:"1e2b516905991c7d7c96fcbfb587e4610000000300000000");
vendor[67] = "Windows-XP";
sig[68] = hex2raw(s:"09002689dfd6b712");
vendor[68] = "XAUTH";


# The Exchange Types that we will try
ext[0] = raw_string(2);
ext[1] = raw_string(1);
ext[2] = raw_string(4);





# MAIN()


 
for (e=0; ext[e]; e++)
{
	ET = ext[e];
	IC = NULL;
	for (cookie=0; cookie<8; cookie++)
		IC += raw_string(rand() % 256);

    	blat = calc_data();
	IC = NULL;
        for (cookie=0; cookie<8; cookie++)
                	IC += raw_string(rand() % 256);

    	oneoff = strlen(blat);
	filter = string("udp and src ", get_host_ip(), " and src port 500 and dst ", this_host());

    	ip = forge_ip_packet(           ip_v : 4,
                                        ip_hl : 5,
                                        ip_tos : 0,
                                        ip_len : 20,
                                        ip_id : 0xABBA,
                                        ip_p : IPPROTO_UDP,
                                        ip_ttl : 255,
                                        ip_off : 0,
                                        ip_src : this_host(),
                                        ip_dst : get_host_ip());

	srcport = rand() % 65535;

    	udpip = forge_udp_packet(               ip : ip,
                                                uh_sport : srcport,
                                                uh_dport : port,
                                                uh_ulen : oneoff + 8,
                                                data : blat);

    	live = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:2);

	if (! live)
	{
        	# well, some implementations of IPSEC (Microsoft,...)
        	# will receive a packet from src port != 500 and dst port=500
        	# and reply from src port == 500 dst port == 500

		udpip = forge_udp_packet(ip : ip,
					uh_sport : port,
					uh_dport : port,
					uh_ulen : oneoff + 8,
					data : blat);

		live = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:2);
	}


    	if (live) 
	{
		#live2 = get_udp_element(udp:live, element:"data");
               	for (j=0; sig[j]; j++)
               	{
                   	if (sig[j] >< live)
                       	{
				desc["english"] += '\n\nPlugin output :\n\n' + 'Vendor : ' + sig[j];
                                	security_warning(port:port, data:desc["english"], protocol:"udp");
                                	register_service(port: port, proto: "ike", ipproto: "udp");
                                	exit(0);
                        }
               	}


        	if (  (ord(live[44]) == 0x0B) && (ord(live[46]) == 0x05)  )
        	{
          		security_warning(port:port, protocol:"udp");
          		register_service(port: port, proto: "ike", ipproto: "udp");
			exit(0);
        	}
	}
}

exit(0);

