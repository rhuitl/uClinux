#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18636);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14166, 14172);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17788");
    script_xref(name:"OSVDB", value:"17789");
    script_xref(name:"OSVDB", value:"17790");
  }

  name["english"] = "phpWebSite <= 0.10.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection and directory traversal attacks. 

Description :

The remote host is running a version of phpWebSite that suffers from
multiple flaws :

  - Multiple SQL Injection Vulnerabilities
    An attacker can affect database queries through the 
    parameters 'module' and 'mod' of the script 'index.php'.
    This may allow for disclosure of sensitive information,
    attacks against the underlying database, and the like.

  - A Directory Traversal Vulnerability
    An attacker can read arbitrary files on the remote host
    by using instances of the substring '../' in the 'mod' 
    parameter of the script 'index.php'.
    
See also : 

http://www.hackerscenter.com/Archive/view.asp?id=3489
http://phpwebsite.appstate.edu/index.php?module=announce&ANN_user_op=view&ANN_id=989

Solution : 

Apply the security patch referenced in the vendor's advisory.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects multiple vulnerabilities in phpWebSite <= 0.10.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family("CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("phpwebsite_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection flaws.
  req = http_get(
    item:string(
      dir, "/index.php?",
      # nb: this should just produce a SQL syntax error.
      "module=", SCRIPT_NAME, "'&",
      "search_op=search&",
      "mod=all&",
      "query=1&",
      "search=Search"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a SQL error.
  if (
    egrep(
      string:res, 
      pattern:string("syntax error<.+ FROM mod_search WHERE module='", SCRIPT_NAME)
    )
  ) {
    security_warning(port);
    exit(0);
  }
}
