#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# Did not really check CVE-2002-1276, since it`s the same kind of problem.
#

if (description)
{
 script_id(11415);
 script_bugtraq_id(6302, 7019);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-1276", "CVE-2002-1341");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:0042-07");

 script_name(english:"SquirrelMail's Cross Site Scripting");
 desc["english"] = "
The remote host seems to be vulnerable to a security problem in
SquirrelMail. Its script 'read_body.php' didn't filter out user input for
'filter_dir' and 'mailbox', making a xss attack possible.

Solution: Upgrade to a newer version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


check1 = string("<script>alert(document.cookie)</script>");
check2 = string("%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E");

foreach d (cgi_dirs())
{
 url = string(d, "/read_body.php");
 data = string(url, "?mailbox=",
"<script>alert(document.cookie)</script>&passed_id=",
"<script>alert(document.cookie)</script>&",
"startMessage=1&show_more=0");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);
 if (check1 >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
# if (check2 >< buf)
#   {
#    security_hole(port:port);
#    exit(0);
#   }
}
