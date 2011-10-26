#
# (C) Tenable Network Security
#


if (description) {
  script_id(17240);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0615", "CVE-2005-0616", "CVE-2005-0617");
  script_bugtraq_id(12683, 12684, 12685);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14282");
    script_xref(name:"OSVDB", value:"15922");
    script_xref(name:"OSVDB", value:"15923");
    script_xref(name:"OSVDB", value:"15924");
  }

  script_name(english:"Multiple Vulnerabilities in PostNuke 0.760 RC2 and older");
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running PostNuke version 0.760 RC2 or older.  These
versions suffer from several vulnerabilities, among them :

  - SQL injection vulnerability in the News, NS-Polls and 
    NS-AddStory modules.
  - SQL injection vulnerability in the Downloads module.
  - Cross-site scripting vulnerabilities in the Downloads
    module.
  - Possible path disclosure vulnerability in the News module.

An attacker may use the SQL injection vulnerabilities to obtain the
password hash for the administrator or to corrupt the database
database used by PostNuke. 

Exploiting the XSS flaws may enable an attacker to inject arbitrary
script code into the browser of site administrators leading to
disclosure of session cookies. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-02/0471.html
http://news.postnuke.com/Article2669.html

Solution : 

Either upgrade and apply patches for 0.750 or upgrade to 0.760 RC3 or
later. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Detects multiple vulnerabilities in PostNuke 0.760 RC2 and older");

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


kb = get_kb_item("www/" + port + "/postnuke" );
if (! kb) exit(0);
install = eregmatch(pattern:"(.*) under (.*)", string:kb );
ver = install[1];
dir = install[2];


# Try the SQL injection exploits.
exploits = make_list(
  "/index.php?catid='cXIb8O3",
  "/index.php?name=Downloads&req=search&query=&show=cXIb8O3",
  "/index.php?name=Downloads&req=search&query=&orderby="
);
foreach exploit (exploits) {
  req = http_get(item:string(dir, exploit), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # See any errors?
  if (res =~ "(DB Error: getArticles:|Fatal error: .+/modules/Downloads/dl-search.php)") {
    security_warning(port);
    exit(0);
  }
}
