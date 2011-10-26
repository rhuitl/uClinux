#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10124);
 script_bugtraq_id(502, 504, 506, 914);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1046", "CVE-2000-0056");
 name["english"] = "Imail's imonitor buffer overflow";
 name["francais"] = "Dépassement de buffer dans imonitor de imail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 
 desc["english"] = "
A buffer overflow in the remote imonitor server allows an intruder to 
execute arbitrary code on this host.

Risk factor : High
Solution : Upgrade your imonitor server to the newest version";
 
 desc["francais"] = "Un dépassement de buffer dans
le serveur imonitor permet à un intrus d'executer du code
arbitraire sur cette machine.

Facteur de risque : Elevé.

Solution : Mettez à jour votre serveur imonitor";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 summary["english"] = "Imail's imonitor buffer overflow"; 
 summary["francais"] = "Dépassement de buffer dans imonitor de imail";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 	 	  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_require_ports("Services/imonitor", 8181);	
 script_dependencies("find_service.nes");       
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/imonitor");
if(!port)port = 8181;

if( safe_checks())
{
 if(!get_port_state(port))exit(0);
 banner = get_http_banner(port:port);
 if( banner == NULL ) exit(0);

 if(egrep(pattern:"^Server: IMail_Monitor/([0-5]\.|6\.[01][^0-9])", string:banner))
	security_hole(port);
 exit(0);
}



if(get_port_state(port))
{
 data = string(crap(2045), "\r\n\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!strlen(buf)){
  	security_hole(port);
	set_kb_item(name:"imonitor/overflow", value:TRUE);
	}
  close(soc);
 }
}
