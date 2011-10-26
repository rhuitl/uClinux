#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10024);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0002");
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "BackOrifice";
 name["francais"] = "BackOrifice";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This host seems to be running a passwordless
BackOrifice 1.x  on this port.

BackOrifice is trojan which allows an intruder to take
the control of the remote computer.

An attacker may use it to steal your passwords, modify
your data, and preventing you from working properly.

Solution : reinstall your system
Risk factor : High";


 desc["francais"] = "
Cette machine semble faire tourner BackOrifice 1.x 
sans mot de passe sur ce port.

BackOrifice est un cheval de troie qui
permet à un intrus de prendre le controle de 
ce poste à distance.

Un pirate peut l'utiliser pour voler vos mots de passe,
modifier vos données, et vous empecher de travailler
correctement.

Solution : réinstallez le système
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the presence of BackOrifice";
 summary["francais"] = "Détermine la présence de BackOrifice";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("os_fingerprint.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);
os = get_kb_item("Host/OS/icmp");
if(os)
{
 if("Windows" >!< os)exit(0);
}

if(!(get_udp_port_state(31337)))exit(0);

#
# Reverse-engineered data. Not very meaningful.
# This is a 'ping' request for BackOrifice
#

s = raw_string(0xCE, 0x63, 0xD1, 0xD2, 0x16, 0xE7, 
	       0x13, 0xCF, 0x39, 0xA5, 0xA5, 0x86, 
	       0x4D, 0x8A, 0xB4, 0x66, 0xAA, 0x32);
	    
soc = open_sock_udp(31337);
send(socket:soc, data:s, length:18);
r = recv(socket:soc, length:10);
if(r)security_hole(31337);
close(soc);
