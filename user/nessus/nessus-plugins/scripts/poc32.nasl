#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10341);
 script_bugtraq_id(1032);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0225");
 
 name["english"] = "Pocsag password";
 name["francais"] = "mot de passe pocsage";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to log into the remote pocsag
service and view the streams of decoded pager
messages using the password 'password' 

An attacker may use this problem to gain some
knowledge about the computer user and then trick him
by social engineering.

Solution : change the password to a random one, or
           filter incoming connections to this port
Risk factor : Low";


 desc["francais"] = "
Il est possible de se logguer dans le service pocsage
distant, et de voir les flux de messages de pager décodés,
en utilisant le mot de passe 'password'

Un pirate peut utiliser ce problème pour obtenir
plus d'informations sur l'utilisateur de ce poste
afin de pouvoir abuser de lui par social engineering.

Solution : changez le mot de passe de ce service pour un mot
           de passe aléatoire, ou filtrez les connections en
	   direction de ce port.
	   
Facteur de risque : faible";	 

 

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "log in using password 'password'";
 summary["francais"] = "se loggue avec le mot de passe 'password'";

 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");

 family["english"] = "Misc.";
 family["francais"] = "Divers";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(8000);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 8000;

if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ( ! buf || "Remote Access" >!< buf ) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  r = telnet_negotiate(socket:soc);
  if("Remote Access" >< r)
   {
   data = string("password\r\n");
   send(socket:soc, data:data);
   
   b = recv_line(socket:soc, length:1024);
   while(b)
   {
   if("Password accepted." >< b)
   {
    security_warning(port);
    close(soc);
    exit(0);
    }
   b = recv_line(socket:soc, length:1024);
  }
  close(soc);
  }
 }
}
