#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10476);
 script_bugtraq_id(1492);
 script_cve_id("CVE-2000-0623");
 script_version ("$Revision: 1.18 $");
 
 
 name["english"] = "WebsitePro buffer overflow";
 name["francais"] = "Website Pro buffer overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server is affected by remote buffer overflows.

Description :

The remote web server is WebSitePro < 2.5.

There are remotely-exploitable buffer overflow vulnerabilities in
releases of WebSitePro prior to 2.5. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-07/0271.html

Solution : 

Upgrade to WebSitePro 2.5 or newer.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WebSitePro";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/websitepro");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: WebSitePro/2\.[0-4].*", string:banner))
     security_hole(port);
}

