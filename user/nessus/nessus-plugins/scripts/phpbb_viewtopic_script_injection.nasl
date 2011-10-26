#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16200);
 script_bugtraq_id(10701);

 script_version("$Revision: 1.3 $");
 name["english"] = "phpBB < 2.0.11";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of phpBB older than 2.0.11.

It is reported that this version of phpBB is susceptible to a script
injection vulnerability which may allow an attacker to execute arbitrary
code on the remote host.

Solution : Upgrade to phpBB 2.0.11 or later
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of phpBB";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
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
if(!get_port_state(port)) exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

version = matches[1];
if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:version))
	security_hole(port);

