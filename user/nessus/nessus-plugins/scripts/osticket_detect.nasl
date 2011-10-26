#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
desc["english"] = "
This script detects whether the target is running osTicket and extracts
version numbers and locations of any instances found.

osTicket is a PHP-based open source support ticket system. See
http://www.osticket.com/ for more information.";


if (description) {
  script_id(13858);
  script_version("$Revision: 1.5 $");
 
  name["english"] = "osTicket Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(1);
if (!can_host_php(port:port)) exit(1);


# Search for osTicket.
installs = 0;
foreach dir (cgi_dirs()) {
  # Get osTicket's open.php.
  url = string(dir, "/open.php");
  debug_print("checking '", url, "'.");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1);
  debug_print("res =>>", res, "<<.");

  # Make sure the page is from osTicket.
  if (egrep(pattern:'alt="osTicket', string:res, icase:TRUE)) {
    pat = "alt=.osTicket STS v(.+) *$";
    debug_print("grepping results for '", pat, "'.");
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      debug_print("grepping '", match, "' for '", pat, "'.");
      ver = eregmatch(pattern:pat, string:match);
      if (ver == NULL) break;
      ver = ver[1];

      # 1.2.5, 1.2.7, and 1.3.x all report 1.2; try to distinguish among them.
      if (ver == "1.2") {
        # 1.3.0 and 1.3.1.
        if ("Copyright &copy; 2003-2004 osTicket.com" >< res) {
          # nb: 1.3.1 doesn't allow calling 'include/admin_login.php' directly.
          url = string(dir, "/include/admin_login.php");
          debug_print("checking '", url, "'.");
          req = http_get(item:url, port:port);
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
          if (res == NULL) exit(1);
          debug_print("res =>>", res, "<<.");

          if ("<td>Please login:</td>" >< res) {
            ver = "1.3.0";
          }
          else if ("Invalid path" >< res) {
            ver = "1.3.1";
          }
          else {
            ver = "unknown";
            if (log_verbosity > 1) debug_print("can't determine version (1.3.x series)", level:0);
          }
        }
        # 1.2.5 and 1.2.7
        else {
          # nb: 1.2.5 has an attachments dir whereas 1.2.7 has attachments.php
          url = string(dir, "/attachments.php");
          debug_print("checking '", url, "'.");
          req = http_get(item:url, port:port);
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
          if (res == NULL) exit(1);
          debug_print("res =>>", res, "<<.");

          if ("You do not have access to attachments" >< res) {
            ver = "1.2.7";
          }
          else if ("404 Not Found" >< res) {
            ver = "1.2.5";
          }
          else {
            ver = "unknown";
            if (log_verbosity > 1) debug_print("can't determine version (1.2.x series)", level:0);
          }
        }
      }
      debug_print("osTicket version '", ver, "'.");

      # Success!
      set_kb_item(
        name:string("www/", port, "/osticket"), 
        value:string(ver, " under ", dir)
      );
      installations[dir] = ver;
      ++installs;

      # nb: only worried about the first match.
      break;
    }
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of osTicket was detected on the remote host under\nthe path ", dir, ".");
    }
    else {
      info = string("osTicket ", ver, " was detected on the remote host under the path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of osTicket were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc["english"],
    pattern:"This script[^\.]+\.",
    replace:info
  );
  security_note(port:port, data:desc);
}
