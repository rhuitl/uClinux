#
# (C) Tenable Network Security
# 
if(description)
{
 script_id(11932);
 script_bugtraq_id(9114);
 script_cve_id("CVE-2003-0914");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:047");

 script_version ("$Revision: 1.6 $");
 
 
 name["english"] = "BIND vulnerable to negative cache poison bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its version number, is vulnerable to 
the negative cache poison  bug that may allow an attacker to disable this
service remotely.

Solution : upgrade to bind 8.3.7 or 8.4.3
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers, pattern:"^8\.([0-2]\.|3\.[0-6]([^0-9]|$)|4\.[0-2]([^0-9]|$))"))security_hole(53);
