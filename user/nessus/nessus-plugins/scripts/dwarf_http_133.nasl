#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21092);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-0819", "CVE-2006-0820");
  script_bugtraq_id(17123);

  script_name(english:"Dwarf HTTP Server < 1.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Dwarf HTTP Server");
 
  desc = "
Synopsis :

The remote web server suffers from multiple flaws.

Description :

The remote host is running Dwarf HTTP Server, a full-featured,
Java-based web server. 

According to its banner, the version of Dwarf HTTP Server on the
remote host reportedly fails to properly validate filename extensions
in URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially-crafted requests with dot, space, slash, and NULL
characters. 

In addition, the web server also reportedly fails to sanitize requests
before returning error pages, which can be exploited to conduct
cross-site scripting attacks. 

See also :

http://secunia.com/secunia_research/2006-13/advisory/

Solution :

Upgrade to Dwarf HTTP Server version 1.3.3 or later. 

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


if (report_paranoia < 2) exit(0);


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (!banner) exit(0);

if (egrep(pattern:"^server: Dwarf HTTP Server/(0\.|1\.([0-2]\.|3\.[0-2] ))", string:banner)
) security_note(port);
