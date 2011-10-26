#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10094);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "GirlFriend";
 name["francais"] = "GirlFriend";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "GirlFriend is installed. 

This backdoor allows anyone to
partially take the control of 
the remote system.

An attacker may use it to steal your
password or prevent your from working
properly.

Solution : 
To remove GirlFriend from your machine, 
open regedit to 
HKLM\Software\Microsoft\Windows\CurrentVersion\Run 
and look for a value named 'Windll.exe'
with the data 'c:\windows\windll.exe'. Reboot 
to DOS and delete the C:\windows\windll.exe file, 
then boot to Windows and remove the 'Windll.exe'
registry value.

Risk factor : High";


 desc["francais"] = "GirlFriend est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : 
To remove GirlFriend from your machine, 
open regedit to 
HKLM\Software\Microsoft\Windows\CurrentVersion\Run 
and look for a value named 'Windll.exe'
with the data 'c:\windows\windll.exe'. Reboot 
to DOS and delete the C:\windows\windll.exe file, 
then boot to Windows and remove the 'Windll.exe'
registry value.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of GirlFriend";
 summary["francais"] = "Détermines la presence de GirlFriend";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(21554,21544);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

#1.0 beta
port = 21554;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}

#1.3 and 1.35
port = 21544;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}
