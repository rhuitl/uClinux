#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(16136);
 script_bugtraq_id(12243);
 
 script_version("$Revision: 1.2 $");
 name["english"] = "GNU Mailman Multiple Unspecified Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "The remote host is running GNU Mailman,
a web based software to manage mailing lists. There are
multiple flaws like information disclosure and cross site
scripting in the remote version of this software which may
allow an attacker to steal user's cookie to gain unauthorized
access.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "GNU Mailman unspecified vulnerabilities";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("mailman_password_retrieval.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/Mailman");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([0-1]\.|2\.(0\.|1\.[0-5][^0-9]))", string:version) )
	security_hole ( port );
