#
# (C) Tenable Network Security
#

if (description)
{
 script_id(15859);
 script_bugtraq_id(11764);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12145");
 }
 script_version ("$Revision: 1.3 $");

 script_name(english:"YaBB Shadow BBCode Tag JavaScript Injection Issue");
 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is prone to 
cross-site scripting attacks.

Description :

The remote host is using the YaBB web forum software. 

According to its version number, the remote version of this software
is vulnerable to Javascript injection issues using shadow or glow
tags.  This may allow an attacker to inject hostile Javascript into
the forum system, to steal cookie credentials or misrepresent site
content.  When the form is submitted the malicious Javascript will be
incorporated into dynamically generated content. 

See also : 

http://www.yabbforum.com/community/YaBB.pl?board=general;action=display;num=1101400965

Solution: 

Upgrade to YaBB 1 Gold SP 1.4 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of YaBB");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if (thorough_tests) dirs = make_list("/yabb", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 url = string(dir, "/YaBB.pl");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:"Powered by.*YaBB (1 Gold - (Release|SP1(\.[1-2].*|3(\.(1|2))?)))", string:buf) ||
    egrep(pattern:"Powered by.*YaBB (1\.([0-9][^0-9]|[0-3][0-9]|4[0-1])(\.0)?)",string:buf) ||
    egrep(pattern:"Powered by.*YaBB (9\.([0-1][^0-9]|1[0-1])(\.[0-9][^0-9]|[0-9][0-9][^0-9]|[0-9][0-9][0-9][^0-9]|[0-1][0-9][0-9][0-9][^0-9]|2000)?)",string:buf))	
   {
    security_note(port);
    exit(0);
   }
}
