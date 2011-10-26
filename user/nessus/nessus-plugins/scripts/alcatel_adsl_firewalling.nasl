#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
   script_id(10760);
   script_cve_id("CVE-2001-1424", "CVE-2001-1425");
   script_bugtraq_id(2568);
   script_version ("$Revision: 1.11 $");
   name["english"] = "Alcatel ADSL modem with firewalling off";
   name["francais"] = "Modem ADSL Alcatel avec Firewalling off";
   script_name(english:name["english"]);
 
   desc["english"] = "
On the Alcatel Speed Touch Pro ADSL modem, a protection mechanism 
feature is available to ensure that nobody can gain remote access 
to the modem (via the WAN/DSL interface). This mechanism guarantees 
that nobody from outside your network can access the modem and 
change its settings.

The protection is currently not activated on your system.

Solution : Telnet to this modem and adjust the security
settings as follows:
=> ip config firewalling on
=> config save 

More information : http://www.alcatel.com/consumer/dsl/security.htm

Risk factor : High";

 desc["francais"] = "
Dans le Speed Touch Pro, un dispositif de protection est
mis en place pour s'assurer que personne ne peut prendre
accès à distance au modem (ou par l'intermédiaire du WAN/DSL).
Ce mécanisme garantit que personne de l'extérieur ne peut
accéder au modem et changer la configuration du modem. 

La protection is not activated

Solution: faites un telnet sur ce modem et ajustez les
paramètres de sécurité comme suit:
=> ip config firewalling on
=> config save 
Plus d'informations : http://www.alcatel.com/consumer/dsl/security.htm

Facteur de risque : Elevé";

   script_description(english:desc["english"], francais:desc["francais"]);
 
   summary["english"] = "Checks Alcatel ADSL modem protection";
   summary["francais"] = "Verifie la protection du modem Alcatel ADSL";
   script_summary(english:summary["english"], francais:summary["francais"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com",
                francais:"Ce script est Copyright (C) 2001 Alert4Web.com");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(23);
 
   exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests && ! ereg(pattern:"^10\.0\.0\..*", string:get_host_ip())) exit(0);

port = 23; # alcatel's ADSL modem telnet module can't bind to something else

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:160);
   if("User : " >< r)
   {
     send(socket:soc, data:string("\r\n"));
     r = recv(socket:soc, length:2048);
     if("ALCATEL ADSL" >< r)
     {
       s = string("ip config\r\n");
       send(socket:soc, data:s);
       r = recv(socket:soc, length:2048);
       if("Firewalling off" >< r)security_hole(port);
     }
   }
   close(soc);
 }
}
