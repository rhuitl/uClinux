#
# (C) Tenable Network Security
# 


if (description) {
  script_id(20013);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3518");
  script_bugtraq_id(15114);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20018");
  }

  script_name(english:"PunBB old_searches Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for old_searches parameter SQL injection vulnerability in PunBB");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description :

The version of PunBB installed on the remote host fails to sanitize
user-supplied input to the 'old_searches' parameter of the
'search.php' script before using it in database queries.  Provided
PHP's 'register_globals' setting is enabled, an attacker may be able
to exploit this issue to delete arbitrary data or launch attacks
against the underlying database. 

See also :

http://www.securityfocus.com/archive/1/413481

Solution : 

Upgrade to PunBB 1.2.9 or later.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:I)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  #
  # nb: the exploit only works if the search returns results.
  req = http_get(
    item:string(
      dir, "/search.php?",
      "action=search&",
      "keywords=&",
      # nb: ensure we get a result.
      "author=*&",
      "forum=-1&",
      "search_in=all&",
      "sort_by=0&",
      "sort_dir=DESC&",
      "show_as=topics&",
      "search=Submit&",
      # nb: this will just give us a syntax error. 
      "old_searches[]='", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an error claiming punBB can't delete the search results.
  if ("Unable to delete search results" >< res) {
    security_note(port);
    exit(0);
  }
}
