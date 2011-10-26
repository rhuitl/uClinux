#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: aCiDBiTS
#
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15462);
 script_cve_id("CVE-2004-2193");
 script_bugtraq_id(11359);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "CjOverkill trade.php XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server runs a version of CjOverkill, a free traffic trading 
script which is as old as or older than version 4.0.3.

The remote version of this software is affected by a cross-site scripting 
vulnerability in the script 'trade.php'. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication credentials 
as well as other attacks.

Solution : Upgrade to version 4.0.4 or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check CjOverkill version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
		
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port) exit(0);
if(!can_host_php(port:port))exit(0);

if(get_port_state(port))
{
 buf = http_get(item:"/trade.php", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<title>CjOverkill Version ([0-3]\.|4\.0\.[0-3][^0-9])</title>", string:r)) security_warning(port);
}
