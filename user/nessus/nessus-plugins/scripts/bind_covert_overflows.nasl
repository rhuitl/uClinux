#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10605);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0001");
 script_bugtraq_id(2302, 2307, 2309, 2321);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0010", "CVE-2001-0011", "CVE-2001-0012", "CVE-2001-0013");
 
 
 name["english"] = "BIND vulnerable to overflows";
 name["francais"] = "BIND vulnerable a des overflows";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to various buffer
overflows that may allow an attacker to 
gain a shell on this host.

Solution : upgrade to bind 8.2.3 or 4.9.8
Risk factor : High";


 desc["francais"] = "
D'après son numéro de version, le serveur BIND distant
est vulnérable à plusieurs dépassements de buffer
permettant à un pirate de passer root sur ce système.

Solution : mettez à jour BIND en 8.2.3 ou 4.9.8
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.(([0-1].*)|(2\.[0-2])).*"))security_hole(53);

if(ereg(string:vers,
    	pattern:"^4\.([0-8]|9\.[0-7]([^0-9]|$)).*"))security_hole(53);

