#
# (C) Tenable Network Security
#


if (description) {
  script_id(19697);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-4806");
  script_bugtraq_id(14788);

  name["english"] = "Sun Java System Web Proxy Server Unspecified Remote Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote proxy server is prone to a denial of service attack. 

Description :

The remote host is running Java System Web Proxy Server / Sun ONE Web
Proxy Server. 

According to its banner, the installed Web Proxy Server reportedly
suffers from an unspecified remote denial of service vulnerability. 
By exploiting this flaw, an attacker could cause the affected
application to fail to respond to further requests. 

See also : 

http://sunsolve.sun.com/search/document.do?assetkey=1-26-101913-1

Solution : 

Upgrade to Web Proxy Server 3.6 Service Pack 8 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for unspecified remote denial of service vulnerability in Sun Java System Web Proxy Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  "Web-Proxy-Server/" >< banner &&
  banner =~ "^Forwarded: .* \(Sun-.+-Web-Proxy-Server/([0-2]\..*|3\.([0-5]\..*|6(\)|-SP[0-7])))"
) security_note(port);
