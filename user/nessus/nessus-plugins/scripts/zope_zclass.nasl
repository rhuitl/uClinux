#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10777);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0567");
 
 name["english"] = "Zope ZClass Permission Mapping Bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that is prone
to a privilege escalation flaw.

Description :

The remote web server uses a version of Zope which is older than
version 2.3.3.  In such versions, any user can visit a ZClass
declaration and change the ZClass permission mappings for methods and
other objects defined within the ZClass, possibly allowing for
unauthorized access within the Zope instance. 

*** Nessus solely relied on the version number of your server, so if 
*** the hotfix has already been applied, this might be a false positive

See also : 

http://www.zope.org/Products/Zope/Hotfix_2001-05-01/security_alert

Solution : 

Upgrade to Zope 2.3.3 or apply the hotfix referenced in the vendor
advisory above. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:L/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

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
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\..*)|(3\.[0-2]))", 
  		string:banner))
     security_warning(port);
}
