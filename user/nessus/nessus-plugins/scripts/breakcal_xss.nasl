#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14225);
 script_bugtraq_id(10847);
 script_version ("$Revision: 1.10 $");
 name["english"] = "BreakCalendar XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI which is vulnerable to a cross site
scripting vulnerability.

Description :

The remote host seems to be running BreakCalendar, a web based calendar.

The remote version of this software is vulnerable to cross site scripting
vulnerability which may allow an attacker to use the remote host to perform 
attacks against third party users.

Solution : 

Update or disable this CGI suite


Risk factor :

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for BreakCalendar version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);

function check(url)
{
	req = http_get(item:string(url, "/breakcal/calendar.cgi"),
 		port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);
	#Powered by breakcal v1.65pr1
	if(egrep(pattern:"Powered by breakcal v1\.[0-4][0-9]*[^0-9]", string:r))
 	{
 		security_note(port);
		exit(0);
	}
 
}

foreach dir (cgi_dirs())
{
 	check(url:dir);
}
