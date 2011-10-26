#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11002);
 
 script_version ("$Revision: 1.9 $");
 name["english"] = "DNS Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
A DNS server is running on this port. If you do not use it, disable it.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "detects a running name server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 exit(0);
}

#
# We ask the nameserver to resolve 127.0.0.1
#

include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

dns["transaction_id"] = rand() % 65535;
dns["flags"]	      = 0x0010;
dns["q"]	      = 1;

packet = mkdns(dns:dns, query:mk_query(txt:mk_query_txt("1.0.0.127.IN-ADDR.ARPA"), type:0x000c, class:0x0001));

		 
if(get_udp_port_state(53))
{
 soc = open_sock_udp(53);
 send(socket:soc, data:packet);
 r = recv(socket:soc, length:1024);
 if(strlen(r) > 3)
 {
  flags = ord(r[2]);
  if(flags & 0x80){
	security_note(port:53, protocol:"udp");
	set_kb_item(name:"DNS/udp/53", value:TRUE);
	register_service(port: 53, proto: "dns", ipproto: "udp");
	}
 }
}
 
 
if(get_port_state(53))
{ 
 soc = open_sock_tcp(53);
 if(!soc)exit(0);
 len = strlen(packet);
 len_hi = len / 256;
 len_lo = len % 256;
 req = string(raw_string(len_hi, len_lo), packet);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:2, min:2);
 if ( ! r ) exit(0);
 len = ord(r[0]) * 256 + ord(r[1]);
 if ( len > 128 ) len = 128;
 r = strcat(r, recv(socket:soc, length:len, min:len));
 if(strlen(r) > 5)
 {
  flags = ord(r[4]);
  if(flags & 0x80){
  	security_note(53);
	register_service(port: 53, proto: "dns");
	}
 }
}
 
		 
