#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11152);
 script_bugtraq_id(6160);
 script_cve_id("CVE-2002-1219");
if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0011");
if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-a-0006");
if(defined_func("script_xref"))script_xref(name:"SuSE", value:"SUSE-SA:2002:044");
 script_version ("$Revision: 1.9 $");
 
 
 name["english"] = "BIND vulnerable to cached RR overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to the SIG cached
RR overflow vulnerability.

An attacker may use this flaw to gain a shell
on this system.

Solution : Upgrade to bind 8.2.7, 8.3.4 or 4.9.11.

Workaround :  Disable recursion on this server if it's not used
as a recursive name server.

Risk factor : High";


 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.2\.[0-6][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^8\.3\.[0-3][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^4\.9\.([0-9][^0-9]*$|10)"))security_hole(53);	 	 
