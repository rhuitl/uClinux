#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10569);
 script_bugtraq_id(922);
 script_version ("$Revision: 1.16 $");
 # nb: SecurityFocus maps this to CVE-2000-0062, but that refers to
 #     an earlier flaw, announced by Christopher Petrilli:
 #       http://mail.zope.org/pipermail/zope/2000-January/100903.html
 script_cve_id("CVE-2000-1212");
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6283");
 }
 name["english"] = "Zope Image Updating Method";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that fails to
protect stored content from modification by remote users. 

Description :

According to its banner, the remote web server is Zope < 2.2.5.  Such
versions suffer from a security issue involving incorrect protection
of a data updating method on Image and File objects.  Because the
method is not correctly protected, it is possible for users with DTML
editing privileges to update the raw data of a File or Image object
via DTML though they do not have editing privileges on the objects
themselves. 

*** Since Nessus solely relied on the version number of your server, 
*** consider this a false positive if you applied the hotfix already.

See also : 

http://mail.zope.org/pipermail/zope-announce/2000-December/000323.html
http://www.zope.org/Products/Zope/Hotfix_2000-12-18/security_alert

Solution :

Upgrade to Zope 2.2.5 or apply the hotfix referenced in the vendor
advisory above. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zope";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
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

if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\.[0-4]))", 
  		string:banner))
     security_warning(port);
}

