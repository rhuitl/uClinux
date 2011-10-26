#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10702);
 script_bugtraq_id(2458);
 script_version ("$Revision: 1.15 $");
 
 name["english"] = "Zope DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that is prone to
a denial of service issue. 

Description :

The remote web server is Zope < 2.2.5.  Such versions allow any Zope
user to create a denial of service by modifying Zope data structures,
thus rendering the site unusable. 

*** Since Nessus solely relied on the version number of your server, 
*** consider this a false positive if you applied the hotfix already.

Solution : 

Upgrade to Zope 2.2.5 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:R/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zope";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\.[0-4]))", 
  		string:banner))
     security_note(port);
}

