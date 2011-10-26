#
# (C) Tenable Network Security
#

if (description)
{
 script_id(15763);
 script_cve_id("CVE-2004-2456");
 script_bugtraq_id(11688);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11711");
 }
 script_version ("$Revision: 1.7 $");

 script_name(english:"miniBB SQL Injection");
 desc["english"] = "
The remote host is using the miniBB forum management system.

According to its version number, this forum is vulnerable to a
SQL injection attack which may allow an attacker to execute arbitrary
SQL statements against the remote database.

Solution: Upgrade to miniBB 1.7f or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary SQL commands");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("minibb_xss.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/minibb");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (.*)$");
if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7([a-e]|$))", string:matches[1]) )
     security_hole(port);
