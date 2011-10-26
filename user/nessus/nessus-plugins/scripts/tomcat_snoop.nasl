#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10478);
 script_bugtraq_id(1532);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0760");

 name["english"] = "Tomcat's snoop servlet gives too much information";
 name["francais"] = "Le servlet snoop de Tomcat donne trop d'informations";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The 'snoop' tomcat's servlet is installed.
(/examples/jsp/snp/anything.snp)

This servlet gives too much information about 
the remote host, such as the PATHs in use,
the host kernel version and so on...

This allows an attacker to gain more knowledge
about this host, and make more precise attacks
thanks to this.

Solution : delete this servlet

Risk factor : Low";


 desc["francais"] = "
Le servlet 'snoop' est installé
(/examples/jsp/snp/anything.snp)

Ce servlet donne trop d'informations
sur l'hote distant, comme les PATHs
utilisés, la version du kernel, etc, etc...

Ces informations donnent à un pirate plus
de connaissances vis à vis de cette machine,
lui permettant ainsi de mener des attaques
plus précises.

Solution : effacez ce servlet
Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /examples/jsp/snp/anything.snp";
 summary["francais"] = "Vérifie la présence de /examples/jsp/snp/anything.snp";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:8080);
if(!port)exit(0);

if(!get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

soc = http_open_socket(port);
if(soc)
{
 req = http_get(item:"/examples/jsp/snp/anything.snp", port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:r))
 {
  if("Server Info: Tomcat" >< r)
  {
   security_warning(port);
  }
 }
}
