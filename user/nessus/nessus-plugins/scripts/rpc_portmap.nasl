#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10223);
 script_bugtraq_id(205);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0632", "CVE-1999-0189");
 name["english"] = "RPC portmapper";
 name["francais"] = "RPC portmapper";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The RPC portmapper is running on this port.

An attacker may use it to enumerate your list
of RPC services. We recommend you filter traffic
going to this port.

Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the port of the remote rpc portmapper";
 summary["francais"] = "Obtient le port du portmapper rpc distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

# the portmaper
RPC_PROG = 100000;

port = 0;
kb_registered = 0;

ports = make_list(111, 32771);
foreach p (ports)
{
 if(get_udp_port_state(p))
   port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP, portmap:p);
 else
   port = 0;
	  
 if(port)
 {
  if(kb_registered == 0)
  {
   set_kb_item(name:"rpc/portmap", value:p);
   kb_registered = 1;
  }
 register_service(port: p, proto: "portmapper");
 security_note(p);
 }
}
