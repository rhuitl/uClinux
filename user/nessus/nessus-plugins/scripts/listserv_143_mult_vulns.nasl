#
# (C) Tenable Network Security
#


if (description) {
  script_id(18374);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1773");
  script_bugtraq_id(13768);

  name["english"] = "Listserv < 14.3-2005a Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is affected by
multiple issues. 

Description :

According to its version number, the Listserv web interface on the
remote host suffers from several critical and as-yet unspecified
vulnerabilities.  An attacker may be able to exploit these flaws to
execute arbitrary code on the affected system or allow remote denial
of service. 

See also : 

http://www.ngssoftware.com/advisories/listserv_2.txt
http://archives.neohapsis.com/archives/bugtraq/2005-05/0289.html
http://www.nessus.org/u?1360cd6d

Solution : 

Apply the 2005a level set from LSoft.

Risk factor: 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Listserv < 14.3-2005a";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # For each of the possible names for the web interface...
  foreach wa (make_list("wa", "wa.exe", "wa.cgi")) {
    # Try to get the version number of the web interface.
    req = http_get(item:string(dir, "/", wa, "?DEBUG-SHOW-VERSION"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # nb: WA version 2.3.31 corrects the flaw.
    if (res =~ "WA version ([01]\.|2\.([0-2]\.|3\.([0-2]|30)))") {
      security_hole(port);
      exit(0);
    }
  }
}
