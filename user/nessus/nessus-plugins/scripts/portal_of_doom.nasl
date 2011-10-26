#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10186);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "Portal of Doom";
 name["francais"] = "Portal of Doom";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "Portal of Doom is installed. 

This backdoor allows anyone to
partially take the control of 
the remote system.

An attacker may use it to steal your
password or prevent your from working
properly.

Solution : 
open the registry to
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices 
and look for the value named 'String' with the data 
'c:\windows\system\ljsgz.exe'. Boot into DOS mode 
and delete the c:\windows\system\ljsgz.exe file, then boot 
into Windows and delete the 'String' value from the registry.
If you are running Windows NT and are infected, you can 
kill the process with Task Manager, and then remove the 
'String' registry value.

Risk factor : High";


 desc["francais"] = "Portal of Doom est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : 
open the registry to
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices 
and look for the value named 'String' with the data 
'c:\windows\system\ljsgz.exe'. Boot into DOS mode 
and delete the c:\windows\system\ljsgz.exe file, then boot 
into Windows and delete the 'String' value from the registry.
If you are running Windows NT and are infected, you can 
kill the process with Task Manager, and then remove the 
'String' registry value.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of Portal of Doom";
 summary["francais"] = "Détermines la presence de Portal of Doom";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port = 10167;
if(get_udp_port_state(port))
{
 soc = open_sock_udp(port);
 if(soc)
 {
 data = "pod";
 send(socket:soc, data:data, length:3);
 r = recv(socket:soc, length:3);
 if("@" >< r)security_hole(port, protocol:"udp");
 close(soc);
 }
}
