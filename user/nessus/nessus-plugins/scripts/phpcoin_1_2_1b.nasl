#
# (C) Tenable Network Security
#


if (description) {
  script_id(17246);
  script_version("$Revision: 1.8 $");

  if ( NASL_LEVEL >= 2200 )script_cve_id(
    "CVE-2005-0669",
    "CVE-2005-0670",
    "CVE-2005-0932",
    "CVE-2005-0933",
    "CVE-2005-0946",
    "CVE-2005-0947"
  );
  script_bugtraq_id(12686, 12917);
  if (NASL_LEVEL >= 2200 && defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14257");
    script_xref(name:"OSVDB", value:"14279");
    script_xref(name:"OSVDB", value:"14280");
    script_xref(name:"OSVDB", value:"14281");
    script_xref(name:"OSVDB", value:"15043");
    script_xref(name:"OSVDB", value:"15044");
    script_xref(name:"OSVDB", value:"15045");
    script_xref(name:"OSVDB", value:"15046");
    script_xref(name:"OSVDB", value:"15047");
    script_xref(name:"OSVDB", value:"15048");
    script_xref(name:"OSVDB", value:"15160");
    script_xref(name:"OSVDB", value:"15161");
    script_xref(name:"OSVDB", value:"15162");
    script_xref(name:"OSVDB", value:"15163");
  }

  script_name(english:"Multiple Vulnerabilities in phpCOIN 1.2.1b and older");
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application affected by several
flaws. 

Description :

The remote host is running phpCOIN version 1.2.1b or older.  These
versions suffer from several vulnerabilities, among them :

  - A Local File Include Vulnerability
    An attacker can execute arbitrary code in the context of the
    web server user by passing the name of a script or file through 
    the 'page' parameter of the 'auxpage.php' script.

  - Multiple SQL injection vulnerabilities.
    By calling the 'faq' module with a specially crafted 
    'faq_id' parameter or the 'pages' or 'site' modules with a 
    specially crafted 'id' parameter, a remote attacker may be
    able to manipulate SQL queries used by the program, thereby 
    revealing sensitive information or even corrupting the
    database.

  - Multiple cross-site scripting vulnerabilities.
    A remote attacker may be able to inject arbitrary code
    into the 'helpdesk' and 'mail' modules as well as the 
    'login.php' script by appending it to a valid request.
    Successful exploitation may allow an attacker to steal
    authentication cookies or misrepresent site content.

See also :

http://www.gulftech.org/?node=research&article_id=00065-03292005
http://archives.neohapsis.com/archives/bugtraq/2005-03/0508.html
http://forums.phpcoin.com//index.php?showtopic=4210

Solution : 

Apply the 2005-03-14 fix file or later for phpCOIN v1.2.2.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Detects multiple vulnerabilities in phpCOIN 1.2.1b and older");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses", francais:"Abus de CGI");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Search for phpCOIN.
foreach dir (cgi_dirs()) {
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If the main page is from phpCOIN...
  if ('<meta name="generator" content="phpcoin">' >< res) {

    # Try XSS various exploits.
    # nb: various ways to popup a window with "Nessus was here"
    xss = "%3cscript%3ewindow.alert('Nessus%20was%20here')%3c/script%3e";
    exploits = make_list(
      "/mod.php?mod=helpdesk&mode=new%22%3E" + xss,
      "/mod.php?mod=mail&mode=reset&w=user%22%3E" + xss,
      "/login.php?w=user&o=login&e=u%22%3E" + xss
    );
    foreach exploit (exploits) {
      req = http_get(item:string(dir, exploit), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # It's a problem if we see "Nessus was here".
      if ("<script>window.alert('Nessus was here')</script>" >< res) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
