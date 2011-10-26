#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server is affected by remote buffer overflow flaws. 

Description :

The remote host appears to be using ELOG, a web-based electronic
logbook application. 

The version of ELOG installed on the remote host crashes when it
receives HTTP requests with excessive data for the 'mode' and 'cmd'
parameters.  An unauthenticated attacker may be able to exploit these
issues to execute arbitrary code on the remote host subject to the
privileges under which the application runs. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040301.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";


if (description) {
  script_id(20321);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4439");
  script_bugtraq_id(15932);
 
  script_name(english:"ELOG Remote Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks for remote buffer overflow vulnerabilities in ELOG");
 
  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure the server looks like ELOG.
banner = get_http_banner(port:port);
if (banner && "Server: ELOG HTTP" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    if ((report_paranoia > 1) && (egrep(pattern:"^Server: ELOG HTTP ([01]\.|2\.([0-5]\.|6\.0))", string:banner))) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus determined the flaw exists on the remote host based solely\n",
        "on the version number of ELOG found in the banner."
      );
      security_note(port:port, data:report);
      exit(0);
    }
  }
  else {
    # Loop through directories.
    if (thorough_tests) dirs = make_list("/elog", "/demo", cgi_dirs());
    else dirs = make_list(cgi_dirs());

    if (http_is_dead (port:port))
      exit (0);

    foreach dir (dirs) {
      # Try to exploit the flaw to crash the service.
      req = http_get(
        item:string(
          dir, "/?",
          "cmd=", crap(20000)
          ),
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      if (res == NULL) {
        if (http_is_dead(port:port)) {
          security_note(port);
          exit(0);
        }
      }
      else exit(0);
    }
  }
}
