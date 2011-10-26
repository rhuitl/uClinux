#
# (C) Tenable Network Security
#

if (description)
{
 script_id(14806);
 script_cve_id("CVE-2004-2139", "CVE-2004-2140");
 script_bugtraq_id(11235);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10220");
   script_xref(name:"OSVDB", value:"10221");
   script_xref(name:"OSVDB", value:"10222");
 }
 script_version ("$Revision: 1.7 $");

 script_name(english:"YaBB Gold 1 Multiple Input Validation Issues");
 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is affected by
multiple cross-site scripting flaws. 

Description :

The remote host is using the YaBB 1 Gold web forum software. 

According to its version number, the remote version of this software
is vulnerable to various input validation issues which may allow an
attacker to perform cross-site scripting or HTTP splitting attacks
against the remote host. 

See also :

http://www.yabbforum.com/community/YaBB.pl?board=general;action=display;num=1093133233

Solution: 

Upgrade to YaBB 1 Gold SP 1.3.2 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of YaBB 1 Gold");
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
 if(egrep(pattern:"Powered by.*YaBB 1 Gold - (Release|SP1(\.[1-2].*|3(\.1)?))", string:buf))
   {
    security_note(port);
    exit(0);
   }
}
