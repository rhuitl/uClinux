#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11510);
 script_bugtraq_id(7228);
 script_version ("$Revision: 1.9 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0001");
 script_cve_id("CVE-2002-0684");

 name["english"] = "BIND 4.x resolver overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its version number, is vulnerable
to a remote buffer overflow within its resolver code.

An attacker may be able to execute arbitrary code by having
the remote DNS server make a request and send back a malicious
DNS response with an invalid length field.

See also : http://www.securityfocus.com/advisories/308
Solution : upgrade to BIND 4.9.5
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}


vers = get_kb_item("bind/version");
if(!vers)exit(0);

vers = string(vers);
if(vers[0] == "4") 
{ 
 if(ereg(string:vers, pattern:"^4\.([0-8]\..*|9\.[0-4][^0-9]*)"))
 {
  security_hole(port:53, proto:"udp");
  exit(0);
 }
}
