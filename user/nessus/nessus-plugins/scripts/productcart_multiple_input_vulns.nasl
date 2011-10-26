#
# (C) Tenable Network Security
#


if (description) {
  script_id(17971);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0994", "CVE-2005-0995");
  script_bugtraq_id(12990);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15263");
    script_xref(name:"OSVDB", value:"15264");
    script_xref(name:"OSVDB", value:"15266");
    script_xref(name:"OSVDB", value:"15267");
    script_xref(name:"OSVDB", value:"15268");
  }

  name["english"] = "ProductCart Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP script that is affected by
several flaws. 

Description :

The remote host is running a version of the ProductCart shopping cart
software that suffers from several input validation vulnerabilities:

  - SQL Injection Vulnerabilities
    The 'advSearch_h.asp' script fails to sanitize user input to
    the 'idCategory', and 'resultCnt' parameters, allowing an
    attacker to manipulate SQL queries.

  - Multiple Cross-Site Scripting Vulnerabilities
    The application fails to sanitize user input via the 
    'redirectUrl' parameter of the 'NewCust.asp' script, the
    'country' parameter of the 'storelocator_submit.asp' script,
    the 'error' parameter of the 'techErr.asp' script, and the 
    'keyword' parameter of the 'advSearch_h.asp' script before
    using it in dynamically generated web content. An attacker
    can exploit these flaws to cause arbitrary HTML and script
    code to be executed in a user's browser in the context of 
    the affected website.

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple input validation vulnerabilities in ProductCart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Check various directories for ProductCart.
foreach dir (cgi_dirs()) {
  # Try to pull up ProductCart's search page.
  req = http_get(item:string(dir, "/advSearch_h.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's ProductCart, we should see an error message like:
  #   <font face="Arial" size=2>/productcart/pc/advSearch_h.asp</font><font face="Arial" size=2>, line 161</font>
  if (egrep(
    string:res, 
    pattern:">" + dir + "/advSearch_h\.asp<.+, line [0-9]+</font>")
   ) {
    # Try the exploit.
    req = http_get(
      item:string(
        dir, "/advSearch_h.asp?",
        "priceFrom=0&",
        "priceUntil=999999999&",
        # nb: this should just cause a syntax error.
        "idCategory='", SCRIPT_NAME, "&",
        "idSupplier=10&",
        "resultCnt=10&",
        "keyword=Nessus"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we get a syntax error in the query, there's a problem.
    if (string("Syntax error in string in query expression 'idCategory='", SCRIPT_NAME, "'") >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
