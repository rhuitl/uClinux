

# This script was written by John Lampe ... j_lampe@bellsouth.net
#
# Script is based on 
# Citrix Published Application Scanner version 2.0
# By Ian Vitek, ian.vitek@ixsecurity.com
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11138);
 script_bugtraq_id(5817);
 script_version ("$Revision: 1.7 $");
 name["english"] = "Citrix published applications";
 script_name(english:name["english"]);

 desc["english"] = "
Attempt to enumerate Citrix published Applications 
 Risk factor : Medium";


 script_description(english:desc["english"]);

 summary["english"] = "Find Citrix published applications";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 exit(0);
}


#script code starts here

port = 1604;
trickmaster =               raw_string(0x20,0x00,0x01,0x30,0x02,0xFD,0xA8,0xE3);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

get_pa =          raw_string(0x2A,0x00,0x01,0x32,0x02,0xFD);
get_pa = get_pa + raw_string(0xa8,0xe3,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x21,0x00);
get_pa = get_pa + raw_string(0x02,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);

if(!get_udp_port_state(port))exit(0);

soc = open_sock_udp(port);
if (soc) {
    send (socket:soc, data:trickmaster);
    incoming = recv(socket:soc, length:1024);
    close(soc);
    if (incoming) {
	soc = open_sock_udp(port);
        send(socket:soc, data:get_pa);
	incoming = recv(socket:soc, length:1024);
	if(incoming) {
	    mywarning = string("The Citrix server is configured in a way which may allow an external attacker\n");
	    mywarning = string(mywarning, "to enumerate remote services.\n\n");
	    mywarning = string(mywarning, "Risk factor: Medium\n");
	    mywarning = string(mywarning, "Solution: see http://sh0dan.org/files/hackingcitrix.txt for more info");
	    security_warning(port:port, data:mywarning, proto:"udp");
	}
    }
}

