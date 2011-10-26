#
# (C) Tenable Network Security
#


if (description) {
  script_id(18220);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1552");
  script_bugtraq_id(13571);

  name["english"] = "GeoHttpServer Unauthorized Image Access Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server does not properly restrict access to files. 

Description :

The GeoVision Digital Surveillance System installed on the remote host
suffers from a vulnerability that enables anyone to bypass
authentication and view JPEG images stored on the server by calling
them directly. 

See also : 

http://www.esqo.com/research/advisories/2005/100505-1.txt
http://archives.neohapsis.com/archives/bugtraq/2005-05/0106.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for unauthorized image access vulnerability in GeoHttpServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the server both is from GeoVision and tries to authenticate access.
res = http_get_cache(item:"/", port:port);
if (
  res && 
  egrep(string:res, pattern:"^Server: GeoHttpServer") &&
  egrep(string:res, pattern:'<input type="password"')
) {
  # Check for the vulnerability by trying to request up to 16 different images.
  for (i=1; i<=16; i++) {
    req = http_get(item:string("/cam", i, ".jpg"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Check whether the result is a JPEG.
    if (
      (res[0] == 0xff && res[1] == 0xd8) ||
      "JFIF" >< res
    ) {
      security_note(port);
      exit(0);
    }
  }
}
