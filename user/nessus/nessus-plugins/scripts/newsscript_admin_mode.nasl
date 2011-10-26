#
# (C) Tenable Network Security
#


if (description) {
  script_id(17309);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0735");
  script_bugtraq_id(12761);

  name["english"] = "NewsScript Access Validation Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is affected by an
access validation vulnerability. 

Description :

The remote host is running a version of NewsScript.co.uk's NewsScript
that allows a remote attacker to bypass authentication simply by setting
the 'mode' parameter to 'admin', thereby allowing him to add, delete, or
modify news stories and headlines at will. 

See also :

http://www.nessus.org/u?85aba152

Solution : 

Upgrade to a version of NewsScript released on or after March 22, 2005. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for access validation vulnerability in NewsScript";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Let's try the exploit.
  req = http_get(item:string(dir, "/newsscript.pl?mode=admin"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If the results have a link to add a record, there's a problem.
  if (
    "?mode=admin&action=add" >< res &&
    egrep(string:res, pattern:"<a href=[^>]+/newsscript.pl\\?mode=admin&action=add")
  ) {
    security_warning(port);
    exit(0);
  }
}
