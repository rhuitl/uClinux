#
# This script was written by Renaud Deraison
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10554);
 script_bugtraq_id(1957);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-1181");
 
 name["english"] = "RealServer Memory Content Disclosure";
 name["francais"] = "RealServer donne le contenu de sa mémoire";
 script_name(english:name["english"], francais:name["francais"]);
 
desc["english"] = "
The remote Real Server discloses the content of its
memory when issued the request :

	GET /admin/includes/
	
This information may be used by an attacker to obtain
administrative control on this server, or to gain 
more knowledge about it.

Solution : See http://service.real.com/help/faq/security/memory.html

Risk factor : High";



desc["francais"] = "
Le serveur Real Distant envoye le contenu de sa mémoire lorsque
la requète :

	GET /admin/includes/
	
est faite. Cette information peut permettre à un pirate d'obtenir
le controle administratif de ce serveur, ou du moins d'obtenir plus
d'informations à son propos

Solution : http://service.real.com/help/faq/security/memory.html
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "dumps the memory of a real g2 server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_ports(7070, "Services/realserver");
 script_dependencies("find_service.nes");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}


include("http_func.inc");
include('global_settings.inc');

if ( ! thorough_tests )exit(0);

port7070 = get_kb_item("Services/realserver");
if(!port7070)port7070 = 7070;

if(get_port_state(port7070))
{
  if ( ! get_http_banner(port:port7070) ) exit(0);

  req = http_get(item:"/admin/includes", port:port7070);
  soc = http_open_socket(port7070);
  if(soc)
  {
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
   if(" 404 " >< r)
   {
    req = http_get(item:"/admin/includes/", port:port7070);
    soc = http_open_socket(port7070);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:4096);
    headers = http_recv_headers2(socket:soc);
    body = http_recv_body(socket:soc, headers:headers, length:0);
    if("application/octet-stream" >!< headers) exit(0);
    http_close_socket(soc);
    if(strlen(body) > 2)
      security_hole(port7070);
   }
  }
}
