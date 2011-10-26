#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(15780);
 script_bugtraq_id(11716);
 
 script_version("$Revision: 1.2 $");
 name["english"] = "SQL injection in phpBB Login Form";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpBB.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands in the login form.

An attacker may exploit this flaw to bypass the authentication
of the remote host or execute arbitrary SQL statements against
the remote database.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];

if ( ereg(pattern:"^([01]\.|2\.0\.([0-9]|10)([^0-9]|$))", string:version ) )
	security_hole(port);
