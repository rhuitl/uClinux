#
# (C) Tenable Network Security
#


if (description) {
  script_id(21015);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0949");
  script_bugtraq_id(16934);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23616");
  }
  script_name(english:"RaidenHTTPD Script Source Disclosure Vulnerability");
  script_summary(english:"Checks version of RaidenHTTPD");
 
  desc = "
Synopsis :

The remote web server suffers from an information disclosure flaw. 

Description :

The remote host is running RaidenHTTPD, a web server for Windows. 

According to its banner, the version of RaidenHTTPD installed on the
remote Windows host fails to properly validate filename extensions in
URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially-crafted requests with dot, space, and slash
characters. 

See also :

http://secunia.com/secunia_research/2006-15/advisory/
http://forum.raidenftpd.com/showflat.php?Cat=&Board=httpd&Number=47234

Solution :

Upgrade to RaidenHTTPD version 1.1.48 or later. 

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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: RaidenHTTPD/1\.(0\.|1\.([0-9][^[0-9]|([0-3][0-9]|4[0-7])))", string:banner)
) {
  security_note(port);
  exit(0);
}
