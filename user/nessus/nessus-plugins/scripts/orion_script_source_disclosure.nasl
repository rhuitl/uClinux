#
# (C) Tenable Network Security
#


if (description) {
  script_id(21152);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0816");
  script_bugtraq_id(17204);

  script_name(english:"Orion Application Server JSP Script Source Disclosure Vulnerability");
  script_summary(english:"Checks version of Orion");
 
  desc = "
Synopsis :

The remote application server suffers from an information disclosure
flaw. 

Description :

The remote host is running Orion Application Server, an application
server running on a Java2 platform. 

According to its banner, the version of Orion installed on the remote
Windows host fails to properly validate filename extensions in URLs. 
A remote attacker may be able to leverage this issue to disclose the
source of JSP scripts hosted by the affected application using
specially-crafted requests with dot and space characters. 

See also :

http://secunia.com/secunia_research/2006-11/advisory/

Solution :

Upgrade to Orion version 2.0.7 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "smb_nativelanman.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


# nb: avoid false-positives since this is open-source and there
#     are no known exploits.
if (report_paranoia < 2) exit(0);


# The flaw only affects Windows hosts.
os = get_kb_item("Host/OS/smb");
if (!os || "Windows" >!< os) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: Orion/([01]\.|2\.0($|\.[0-6]([^0-9]|$)))", string:banner)
) security_note(port);
