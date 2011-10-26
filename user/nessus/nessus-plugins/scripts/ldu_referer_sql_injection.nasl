#
# (C) Tenable Network Security
#


if (description) {
  script_id(19774);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(14896);

  name["english"] = "Land Down Under HTTP Referer SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL 
injection attacks.

Description :

The installed version of Land Down Under fails to sanitize input passed
through the HTTP Referer header before using it in database queries. 
Provided PHP's 'magic_quotes_gpc' setting is disabled, an attacker can
exploit this issue to manipulate database queries, possibly revealing
sensitive information or corrupting arbitrary data. 

Solution : 

Enable PHP's 'magic_quotes_gpc' setting.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HTTP Referer SQL injection vulnerability in Land Down Under";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("ldu_detection.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  req = http_get(item:string(dir, "/"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Referer: nessus'", SCRIPT_NAME, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a syntax error
  if (egrep(string:res, pattern:string("^MySQL error : .+ '", SCRIPT_NAME))) {
    security_warning(port);
    exit(0);
  }
}
