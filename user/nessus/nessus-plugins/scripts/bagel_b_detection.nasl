# 
# (C) Tenable Network Security
#

if(description)
{
 script_id(12063);
 script_version("$Revision: 1.9 $");

 name["english"] = "Bagle.B detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the bagle.B virus installed. 
This is a variant of the Bagel virus which spreads
via email and has a backdoor listener on port 8866.

Solution: Use an antivirus product to remove the virus.
Risk Factor: High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Bagle.B";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(2745, 8866);
 
 exit(0);
}

# so, if we need to add more bagels to the mix....just add them here....
ports[0] = 2745;  desc[0] = "Bagle.Z";
ports[1] = 8866;  desc[1] = "Bagle.B";

for (i=0; ports[i]; i++) {
    if (get_port_state(ports[i]) ) { 
	soc = open_sock_tcp(ports[i]);
	if ( ! soc ) continue;
	close(soc);
        srcaddr = this_host();
        dstaddr = get_host_ip();
        port = ports[i];

        #  gens a RST
        req_rst = raw_string(0x00, 0xA8, 0x00, 0xe6, 0x33, 0x35, 0x37, 0x57, 0x53, 0x00, 0xD0);

        # 00 A8 20 01 1A   generates a FIN
        req_fin = raw_string(0x00, 0xA8, 0x20, 0x01, 0x1A);

        ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


        tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : 44557,
                             th_dport : 139,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);

        filter = string("(src or dst ", srcaddr, ") and (src or dst ", dstaddr, ") and  (src or dst port ", port , " ) ");
        soc = open_sock_tcp(port);
        if (soc) {
            send(socket:soc, data:req_fin);
            result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);
            if (result)  {
                flags = get_tcp_element(tcp:result, element:"th_flags");
            }

            if (flags & TH_FIN) {
              finflag = 1;
            }


            # hunt the RST
            ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


            tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : 44556,
                             th_dport : 139,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);
            filter = string("(src or dst ", srcaddr, ") and (src or dst ", dstaddr, ") and  (src or dst port ", port , " ) ");
            soc2 = open_sock_tcp(port);
            if (soc2) { 
                send(socket:soc2, data:req_rst);
                result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);

                if (result)  {
                    flags = get_tcp_element(tcp:result, element:"th_flags");
                }

                if (flags & TH_RST) {
                    rstflag = 1;
                }


                if (rstflag && finflag) {
                    strain = desc[i]; 
                    mymsg = string("The remote host has the ", strain,  " virus installed.
This is a variant of the Bagle virus which spreads
via email and has a backdoor listener on port ", ports[i] , ".

Solution: Use an antivirus product to remove the virus.
Risk Factor: High");
                    security_hole(port:port, data:mymsg);
                }
                rstflag = finflag = 0;
            } # end if(soc2)
        close (soc); close (soc2);
        } # end if (soc)
    }     # end if (get_port_state(ports[i]) ) {
}         # end for(i=0; etc.




