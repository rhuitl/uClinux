#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Ian Koenig <ian@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#      Updated to handle two specific types of attacks instead of just a general
#        statement of "vulnerable to DNS storm attacks".
#      


if(description)
{
 script_id(10886);
 script_bugtraq_id(6159, 6160, 6161);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-a-0006");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0011");
 if(defined_func("script_xref"))script_xref(name:"SuSE", value:"SUSE-SA:2002:044");
 
 name["english"] = "BIND vulnerable to DNS storm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This is associated with three different vulnerabilities.

1) The remote BIND server, based on its version number, if running
recursive DNS functionality, is vulnerable to a buffer overflow.

2) The remote BIND server is vulnerable to a denial of service (crash) 
via SIG RR elements with invalid expiry times.

3) The remote BIND server is vulnerable to a denial of service.
When a DNS lookup is requested on a non-existent sub-domain of 
a valid domain and an OPT resource record with a large UDP 
payload is attached, the server may fail. 

Solution : upgrade to at least bind 8.3.4
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "General";
 family["francais"] = "General";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);

if(ereg(string:vers,
	 pattern:"^8\.(([0-1].*)|(2\.[0-6])|(3\.0\.[0-3])).*"))security_hole(53);

