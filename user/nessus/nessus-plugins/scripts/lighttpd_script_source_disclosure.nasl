#
# (C) Tenable Network Security
#


if (description) {
  script_id(21155);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0814");
  script_bugtraq_id(16893);
  script_xref(name:"OSVDB", value:"23542");

  script_name(english:"lighttpd Script Source Disclosure Vulnerability");
  script_summary(english:"Checks version of lighttpd");
 
  desc = "
Synopsis :

The remote web server suffers from an information disclosure flaw. 

Description :

The remote host is running lighttpd, an open-source web server with a
light footprint. 

According to its banner, the version of lighttpd installed on the
remote Windows host fails to properly validate filename extensions in
URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially-crafted requests with dot and space characters. 

See also :

http://secunia.com/secunia_research/2006-9/advisory/
http://www.kevinworthington.com:8181/?p=109

Solution :

Upgrade to lighttpd for Windows version 1.4.10a or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: lighttpd/1\.4\.([0-9][^0-9]?|10) \(Win32\)", string:banner)
) security_note(port);
