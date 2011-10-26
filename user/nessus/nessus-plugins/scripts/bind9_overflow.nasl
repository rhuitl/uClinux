#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
# http://www.isc.org/products/BIND/bind9.html
# http://cert.uni-stuttgart.de/archive/bugtraq/2003/03/msg00075.html
# 
#

if(description)
{
 script_id(11318);
 script_cve_id("CVE-2002-0684");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0001");
 script_version ("$Revision: 1.9 $");

 
 name["english"] = "BIND 9 overflow";
 name["francais"] = "BIND 9 overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote BIND 9 DNS server, according to its version number, is vulnerable to a 
buffer overflow which may allow an attacker to gain a shell on this host or 
to disable this server.


Solution : upgrade to bind 9.2.2 or downgrade to the 8.x series

See also : http://www.isc.org/products/BIND/bind9.html
 	   http://cert.uni-stuttgart.de/archive/bugtraq/2003/03/msg00075.html
	   http://www.cert.org/advisories/CA-2002-19.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 summary["francais"] = "Vérifie le numéro de version du BIND distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";

 script_family(english:family["english"]);

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

if(ereg(string:vers, pattern:"^9\.2\.([0-1][^0-9]*|2rc.*)$"))
{
 security_hole(53);
 exit(0);
}
