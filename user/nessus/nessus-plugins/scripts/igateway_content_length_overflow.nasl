#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server is affected by a buffer overflow vulnerability. 

Description :

The remote host is using Computer Associates iTechnology iGateway
service, a software component used in various products from Computer
Associates. 

The version of the iGateway service installed on the remote host
reportedly fails to sanitize Content-Length HTTP header values before
using them to allocate heap memory.  An attacker can supply a negative
value, which causes the software to allocate a small buffer, and then
overflow that with a long URI.  Successful exploitation of this issue
can lead to a server crash or possibly the execution of arbitrary
code.  Note that, under Windows, the server runs with local SYSTEM
privileges. 

See also :

http://www.idefense.com/intelligence/vulnerabilities/display.php?id=376
http://supportconnectw.ca.com/public/ca_common_docs/igatewaysecurity_notice.asp

Solution : 

Contact the vendor to upgrade to iGateway 4.0.051230 or later. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description) {
  script_id(20805);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-3653");
  script_bugtraq_id(16354);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22688");
  }
 
  script_name(english:"iTechnology iGateway Content-Length Buffer Overflow Vulnerability");
  script_summary(english:"Checks for Content-Length buffer overflow vulnerability in iTechnology iGateway");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 5250);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:5250);
if (!get_port_state(port)) exit(0);


# Get a list of all sponsors.
req = http_get(item:"/igsponsor", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);


# If it looks like iGateway...
#
# nb: iGateway doesn't seem to include a server response header
#     there's a valid request.
if (
  res &&
  "Server: iGateway" >< res
) {
  # Pull out the version number components.
  sponsor = strstr(res, "<SponsorName>iControl");
  if (sponsor) {
    ver_maj = strstr(sponsor, "<MajorVersion>");
    if (ver_maj) {
      ver_maj = ver_maj - strstr(ver_maj, "</");
      ver_maj = strstr(ver_maj, ">");
      ver_maj = ver_maj - ">";
    }
    ver_min = strstr(sponsor, "<MinorVersion>");
    if (ver_min) {
      ver_min = ver_min - strstr(ver_min, "</");
      ver_min = strstr(ver_min, ">");
      ver_min = ver_min - ">";
    }
    ver_svc = strstr(sponsor, "<ServicePackVersion>");
    if (ver_svc) {
      ver_svc = ver_svc - strstr(ver_svc, "</");
      ver_svc = strstr(ver_svc, ">");
      ver_svc = ver_svc - ">";
    }
    # Check the version number.
    if (!isnull(ver_maj) && !isnull(ver_min) && !isnull(ver_svc)) {
      iver_maj = int(ver_maj);
      iver_min = int(ver_min);
      iver_svc = int(ver_svc);

      # There's a problem if the version is < 4.0.051230
      #
      # nb: ver_svc is in the form YYMMDD.
      if (
        iver_maj < 4 ||
        (iver_maj == 4 && iver_min == 0 && iver_svc < 51230)
      ) {
        security_hole(port);
      }
    }
  }
}
