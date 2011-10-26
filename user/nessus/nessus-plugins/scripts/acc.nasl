#
# This script was written by Sebastian Andersson <sa@hogia.net>
#
# Changes by rd :
#
# 	- french description
#	- script id
#	- cve id
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10351);
 script_bugtraq_id(183);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-1999-0383");
 
 name["english"] = "The ACC router shows configuration without authentication";
 name["francais"]= "Le routeur ACC donne sa configuration sans authentification";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote router is an ACC router.

Some software versions on this router will allow an attacker to run the SHOW 
command without first providing any authentication to see part of the router's 
configuration.

Solution : Upgrade the software.

Risk factor : Medium";

desc["francais"]  = "
Le routeur distant est un routeur ACC.

Plusieurs versions de celui-ci permettent à un 
intrus d'executer la commande SHOW sans s'authentifier
au préalable, ce qui permet d'obtenir la configuration
de celui-ci.

Solution : mettez le logiciel à jour
Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for ACC SHOW command bug";
 summary["francais"] = "Vérifie le bug de ACC SHOW";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Sebastian Andersson");
 family["english"] = "Remote file access";
 family["francais"]= "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;

banner = get_telnet_banner(port:port);
if ( ! banner || "Login:" >< banner ) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  first_line = telnet_negotiate(socket:soc);
  if("Login:" >< first_line) {
   req = string("\x15SHOW\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   r = recv_line(socket:soc, length:1024);
   if(("SET" >< r) ||
      ("ADD" >< r) ||
      ("RESET" >< r)) {
    security_warning(port);
    # cleanup the router...
    while(! ("RESET" >< r)) {
     if("Type 'Q' to quit" >< r) {
      send(socket:soc, data:"Q");
      close(soc);
      exit(0);
     }
     r = recv(socket:soc, length:1024);
    }
   }
  }
  close(soc);
 }
}
