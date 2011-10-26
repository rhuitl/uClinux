#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11597);
 script_cve_id("CVE-2003-0492", "CVE-2003-0494");
 script_bugtraq_id(7381, 7922, 7925);
 script_version ("$Revision: 1.12 $");

 script_name(english:"Snitz Forums 2000 Password Reset and XSS ");
 desc["english"] = "
The remote host is using Snitz Forum 2000.

This set of CGI is vulnerable to a cross-site-scripting issue
that may allow attackers to steal the cookies of your
users.

In addition to this flaw, a user may use the file Password.ASP to
reset arbitrary passwords, therefore gaining administrative access
on this web system.

Solution: Upgrade to a newer version.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Snitz forums is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list("/forum", cgi_dirs());
		


foreach d (dir)
{
 url = string(d, '/search.asp');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 # Ex: Powered By: Snitz Forums 2000 Version 3.4.03
 if("Powered By: Snitz Forums 2000" >< buf )
   {
    security_hole(port);
    exit(0);
   }
}
