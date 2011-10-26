#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15788); 
 script_bugtraq_id(11631);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Nucleus Multiple Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Nucleus CMS, an open-source content management
system.

The remote version of this software is vulnerable to various flaws which may
allow an attacker to perform a cross site scripting attack using the remote
host and to perform a SQL injection attack on the remote database.

Solution : Upgrade to Nucleus 3.15 or newer
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Nucleus Version Check";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("nucleus_sql_injection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/nucleus");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([0-2]|3\.0|3\.1([^0-9]|$)|3\.1[0-4])", string:version) )
     security_hole(port);
