#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote AJP connector is affected by a denial of service issue. 

Description :

According to its banner, the version of Apache Tomcat installed on the
remote host suffers from a denial of service vulnerability due to its
failure to handle malformed input.  By submitting a specially-crafted
AJP12 request, an unauthenticated attacker can cause Tomcat to stop
responding.  At present, details on the specific nature of such
requests are not generally known. 

See also :

http://www.kb.cert.org/vuls/id/JGEI-6A2LEF

Solution : 

Upgrade to Apache Tomcat version 5.x or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


if (description) {
  script_id(17322);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0808");
  script_bugtraq_id(12795);

  name["english"] = "Apache Tomcat Remote Malformed Request Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote malformed request denial of service vulnerability in Apache Tomcat";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/http", 80);

  exit(0);
}


include ('http_func.inc');


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  "Tomcat" >< banner &&
  egrep(pattern:"^Server: (Apache )?Tomcat( Web Server)?/([12]\..*|3\.(0\.0|1\.[01]|2\.[0-4]|3\.[01]))([^0-9]|$)", string:banner)
) security_note(port);

