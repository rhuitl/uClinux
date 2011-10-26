#
# (C) Tenable Network Security
#


if (description) {
  script_id(17329);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2004-1219",
    "CVE-2004-1551",
    "CVE-2005-0326",
    "CVE-2005-0327",
    "CVE-2005-0723",
    "CVE-2005-0724"
  );
  script_bugtraq_id(7183, 8271, 10229, 11817, 11818, 12758, 12788, 13967);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"12263");
    script_xref(name:"OSVDB", value:"12264");
    script_xref(name:"OSVDB", value:"12265");
    script_xref(name:"OSVDB", value:"12266");
    script_xref(name:"OSVDB", value:"13494");
    script_xref(name:"OSVDB", value:"13495");
    script_xref(name:"OSVDB", value:"14684");
    script_xref(name:"OSVDB", value:"14685");
    script_xref(name:"OSVDB", value:"14686");
    script_xref(name:"OSVDB", value:"14687");
    script_xref(name:"OSVDB", value:"14688");
  }
 
  script_name(english:"Multiple Vulnerabilities in paFileDB 3.1 and older (2)");
  script_summary(english:"Checks for multiple vulnerabilities in paFileDB 3.1 and Older");

  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple issues. 

Description :

The remote host is running a version of paFileDB that is prone to a
wide variety of vulnerabilities, including arbitrary file uploads,
local file inclusion, SQL injection, and cross-site scripting issues. 

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("pafiledb_detect.nasl");
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
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try various SQL injection attacks.
  exploits = make_list(
    "/pafiledb.php?action=viewall&start='&sortby=rating",
    "/pafiledb.php?action=category&start='&sortby=rating"
  );
  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # It's a problem if MySQL encountered a syntax error.
    if (egrep(string:res, pattern:"MySQL Returned this error.+ error in your SQL syntax")) {
      security_warning(port);
      exit(0);
    }
  }
}
