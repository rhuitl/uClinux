#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(13840);
 script_cve_id("CVE-2004-2054", "CVE-2004-2055");
 script_bugtraq_id(10738, 10753, 10754, 10883);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8164");

 script_version("$Revision: 1.12 $");
 name["english"] = "phpBB < 2.0.10";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of phpBB older than 2.0.10.

phpBB contains a flaw that allows a remote cross site scripting attack. 
This flaw exists because the application does not validate user-supplied 
input in the 'search_author' parameter.

This version is also vulnerable to an HTTP response splitting vulnerability
which permits the injection of CRLF characters in the HTTP headers.

Solution : Upgrade to 2.0.10 or later.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for phpBB version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
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
if ( ereg(pattern:"^([01]\.|2\.0\.[0-9]([^0-9]|$))", string:version) )
	security_warning ( port );
