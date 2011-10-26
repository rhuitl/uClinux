
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11365);
 script_bugtraq_id(4069);
 script_cve_id("CVE-2002-0257");
 script_version ("$Revision: 1.12 $");

 name["english"] = "Auction Deluxe XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a
cross site scripting issue.

Description : 

The remote Auction Deluxe server is vulnerable to 
a cross site scripting attack.

As a result, a user could easily steal the cookies
of your legitimate users and impersonate them.

Solution : 

Upgrade to Auction Deluxe 3.30 or newer

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for auction.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


foreach dir ( cgi_dirs() )
{
 req = http_get(item:string(dir, "/auction.pl?searchstring=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))exit(0);

 str = egrep(pattern:"<script>foo</script>", string:res, icase:TRUE);
 if(str)
 {
    security_note(port);
    exit(0);
 }
}
