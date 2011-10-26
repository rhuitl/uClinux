#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11051);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0010");
 script_bugtraq_id(4936);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0400");
 
 name["english"] = "BIND9 DoS";
 name["francais"] = "BIND9 DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to a denial
of service attack.

An attacker may use this flaw to prevent
this service to work properly.

Solution : upgrade to bind 9.2.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de Service";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}




vers = get_kb_item("bind/version");
if(!vers)exit(0);

if(ereg(string:vers, pattern:"^9\.[01]\.*"))
{
 security_hole(53);
 exit(0);
}

if(ereg(string:vers, pattern:"^9\.2\.(0[^0-9]|1rc.*)"))
{
 security_hole(53);
 exit(0);
}
