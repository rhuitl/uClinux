#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15760);
 script_bugtraq_id(11681);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "PowerPortal SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product which may allow 
a remote attacker to perform a SQL injection attack against the remote host.

An attacker may exploit this flaw to execute arbitrary SQL statements against
the remote database and possibly to execute arbitrary commands on the remote
host.

Solution : Upgrade to the latest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PowerPortal Installation";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("powerportal_privmsg_html_injection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/powerportal");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (/.*)$");
if ( ereg(pattern:"^(0\..*|1\.[0-3]([^0-9]|$))", string:matches[1]) )
	security_hole(port);
