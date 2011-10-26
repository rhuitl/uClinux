#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(11938);
 script_cve_id("CVE-2003-1215", "CVE-2003-1216");
 script_bugtraq_id(9122, 9314);
 
 script_version("$Revision: 1.10 $");
 name["english"] = "SQL injection in phpBB (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of phpBB older than 2.0.7.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host or to obtain
the MD5 hash of the password of any user.

Solution : Upgrade to version 2.0.7 or later.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([01]\..*|2\.0\.[0-6]([^0-9]|$))", string:version) )
	security_hole ( port );
