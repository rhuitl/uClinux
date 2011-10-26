#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a CGI application that is affected by
multiple buffer overflow vulnerabilities. 

Description :

The remote host is running Listserv, a mailing list management
application. 

According to its version number, the Listserv install on the remote
host suffers from as-yet unspecified buffer overflows, including one
which reportedly can be exploited by an unauthenticated attacker to
execute arbitrary code on the affected host. 

See also :

http://www.securityfocus.com/archive/1/426770/30/0/threaded
http://www.nessus.org/u?286efa50

Solution :

Upgrade to Listserv 14.5 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(21016);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-1044");
  script_bugtraq_id(16951);

  script_name(english:"Listserv < 14.5 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version number of Listserv");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through various directories.
foreach dir (cgi_dirs()) {
  # For each of the possible names for the web interface...
  foreach wa (make_list("wa", "wa.exe", "wa.cgi")) {
    # Try to get the version number of the web interface.
    req = http_get(item:string(dir, "/", wa, "?DEBUG-SHOW-VERSION"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # nb: Listserv 14.5 == WA version 2.3.42.
    if (res =~ "WA version ([01]\.|2\.([0-2]\.|3\.([0-3]|4[01])))") {
      security_hole(port);
      exit(0);
    }
  }
}
