#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(13647);
  script_version ("$Revision: 1.3 $");
 
  name["english"] = "osTicket setup.php Accessibility";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of an improperly secured
installation of osTicket and allows access to setup.php.  Since that
script does not require authenticated access, it is possible for an
attacker to modify osTicket's configuration using a specially crafted
call to setup.php to perform the INSTALL actions. 

For example, if config.php is writable, an attacker could change the
database used to store ticket information, even redirecting it to
another site.  Alternatively, regardless of whether config.php is
writable, an attacker could cause the loss of all ticket information by
reinitializing the database given knowledge of its existing
configuration (gained, say, from reading config.php). 

Solution : Remove both setup.php and gpcvar.php and ensure permissions
on config.php are 644. 

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks Accessibility of osTicket's setup.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for setup.php Accessibility vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # Get osTicket's setup.php.
    url = string(dir, "/setup.php");
    if (debug_level) display("debug: checking ", url, ".\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # If successful, there's a problem.
    if (egrep(pattern:"title>osTicket Install", string:res, icase:TRUE)) {
      security_warning(port:port);
      exit(0);
    }
  }
}
