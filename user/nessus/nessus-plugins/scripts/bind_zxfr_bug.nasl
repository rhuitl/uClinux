#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10549);
 script_bugtraq_id(1923);
 script_cve_id("CVE-2000-0887");
 script_version ("$Revision: 1.9 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-b-0008"); 
 
 name["english"] = "BIND vulnerable to ZXFR bug";
 name["francais"] = "BIND vulnerable au bug ZXFR";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to the ZXFR
bug that allows an attacker to disable it
remotely.

Solution : upgrade to bind 8.2.2-P7
Risk factor : High";


 desc["francais"] = "
D'après son numéro de verson, le serveur BIND distant
est vulnérable au bug ZXFR qui permet à un pirate
de le désactiver à distance.

Solution : mettez à jour BIND en 8.2.2-P7
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.2\.2(\-P[1-6])*$"))security_hole(53);
