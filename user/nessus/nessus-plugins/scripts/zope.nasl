#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10447);
 script_bugtraq_id(1354);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0483");
 
 name["english"] = "Zope DocumentTemplate package problem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that fails to
protect stored content and code from modification by remote users. 

Description :

The remote web server is Zope < 2.1.7.  There is a security problem in
these versions that can allow the contents of DTMLDocuments or
DTMLMethods to be changed without forcing proper user authentication. 

See also : 

http://mail.zope.org/pipermail/zope/2000-June/111952.html
http://www.zope.org/Products/Zope/Hotfix_06_16_2000/security_alert

Solution : 

Upgrade to Zope 2.1.7 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
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
if(egrep(pattern:"^Server: .*Zope 2\.((0\..*)|(1\.[0-6]))", string:banner))
     security_hole(port);
}
