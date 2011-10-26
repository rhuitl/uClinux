#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(13655);
 script_bugtraq_id(10722);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7811");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7814");

 script_version("$Revision: 1.5 $");
 name["english"] = "SQL injection in phpBB (3)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of phpBB older than 2.0.9.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host or to obtain
the MD5 hash of the password of any user.

One vulnerability is reported to exist in 'admin_board.php'. 
The other pertains to improper characters in the session id variable. 

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
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
if ( ereg(pattern:"^([01]\.|2\.0\.[0-8]([^0-9]|$))", string:version) )
	security_hole(port);
