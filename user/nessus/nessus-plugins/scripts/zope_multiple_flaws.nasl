#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11985);
 script_bugtraq_id(9400);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Zope Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that is prone to
multiple vulnerabilities. 

Description :

The remote web server is a version of Zope which is older than version
2.6.3. 

There are multiple security issues in all releases prior to version 
2.6.3 or 2.7 BETA4 which can be exploited by an attacker to perform cross
site scripting attacks, obtain information about the remote host, or
disable this service remotely.

*** Nessus solely relied on the version number of your server, so if 
*** the hotfix has already been applied, this might be a false positive

See also : 

http://mail.zope.org/pipermail/zope-announce/2004-January/001325.html

Solution : 

Upgrade to Zope 2.6.3 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 summary["english"] = "Checks Zope version"; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
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
  if(egrep(pattern:"Server: .*Zope 2\.(([0-5]\..*)|(6\.[0-2][^0-9])|(7\..*BETA *[0-3]))", 
  		string:banner))
     security_warning(port);
}
