#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10029);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-b-0001");
 script_bugtraq_id(788);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0833", "CVE-1999-0837", "CVE-1999-0848", "CVE-1999-0849");
 
 name["english"] = "BIND vulnerable";
 name["francais"] = "BIND vulnerable";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to several
attacks that can allow an attacker to gain
root on this system.

Solution : upgrade to bind 8.2.2-P5
Risk factor : High
See also : http://www.cert.org/advisories/CA-1999-14.html";


 desc["francais"] = "
D'après son numéro de verson, le serveur BIND distant
est vulnérable à plusieurs attaques permettant à
un pirate de passer root aisément sur le serveur.

Solution : mettez à jour BIND en 8.2.2-P5
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

bind4_warning = "
BIND versions before 4.9.7-REL are vulnerable to some
denial of service attacks.

Solution: upgrade to BIND 8.2.2-P5 or later
           (or BIND 4.9.7-REL)
Risk factor : Medium";




vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if(vers[0] == "4") 
{ 
 if(ereg(string:vers, pattern:"^4\.([0-8]\..*|9\.[0-6]([^0-9]|$))"))
 {
  security_hole(port:53, data:bind4_warning);
  exit(0);
 }
}
else
   if(ereg(string:vers, pattern:"^8\.([01]\..*|2\.([01].*|2-P[0-2]))"))
     	security_hole(53);
