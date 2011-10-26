#
# (C) Tenable Network Security
#


if (description) {
  script_id(20112);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3395");
  script_bugtraq_id(15240);

  script_name(english:"Invision Gallery st Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for st parameter SQL injection vulnerability in Invision Gallery");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote host is running Invision Gallery, a community-based photo
gallery plugin for Invision Power Board. 

The version of Invision Gallery installed on the remote host fails to
properly sanitize user-supplied input to the 'st' parameter of the
'index.php' script before using it in database queries.  An attacker
may be able to leverage this issue to expose or modify sensitive data
or launch attacks against the underlying database. 

See also :

http://www.securityfocus.com/archive/1/415297/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Exploitation requires a valid category.
  req = http_get(item:string(dir, "/?act=module&module=gallery"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  pat = "act=module&amp;module=gallery&amp;cmd=sc&amp;cat=([0-9]+)";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    cat = eregmatch(pattern:pat, string:match);
    if (!isnull(cat)) {
      cat = cat[1];
      break;
    }
  }


  # Try to exploit one of the SQL injection vulnerabilities.
  if (isnull(cat)) {
    if (log_verbosity > 1) debug_print("couldn't find a category to use!", level:0);
  }
  else {
    req = http_get(
      item:string(
        dir, "/index.php?",
        "act=module&",
        "module=gallery&",
        "cmd=sc&",
        "cat=", cat, "&",
        "sort_key=date&",
        "order_key=DESC&",
        "prune_key=30&",
        "st='", SCRIPT_NAME
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a SQL syntax error involving our script name.
    if (
      ("an error in your SQL syntax" >< res) &&
      (string("ORDER BY pinned DESC, date DESC , i.id DESC  LIMIT &amp;#39;", SCRIPT_NAME) >< res)
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
