#
# (C) Tenable Network Security
#


if (description) {
  script_id(18436);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1967", "CVE-2005-2445");
  script_bugtraq_id(13881);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17329");
    script_xref(name:"OSVDB", value:"17330");
  }

  name["english"] = "ProductCart Multiple SQL Injection Vulnerabilities (2)";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple SQL injection issues. 

Description :

The remote host is running a version of the ProductCart shopping cart
software that fails to properly sanitize user-supplied input before
using it in SQL queries.  An attacker may be able to exploit these
flaws to alter database queries, disclose sensitive information, or
conduct other such attacks.  Possible attack vectors include the
'idcategory' parameter of the 'viewPrd.asp' script, the 'lid'
parameter of the 'editCategories.asp' script, the 'idc' parameter of
the 'modCustomCardPaymentOpt.asp' script, and the 'idccr' parameter of
the 'OptionFieldsEdit.asp' script. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-07/0521.html
http://echo.or.id/adv/adv16-theday-2005.txt

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple SQL injection vulnerabilities (2) in ProductCart";
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
  # nb: the exploit requires a valid product id.

  # Try to pull up ProductCart's list of categories.
  req = http_get(item:string(dir, "/viewCat.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like ProductCart...
  if (res =~ "<a href=viewCat.asp>.+Our Products</a>") {
    # Get category ids.
    ncats = 0;
    pat = "href='viewCat_h.asp?idCategory=([0-9]+)'>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cat = eregmatch(pattern:pat, string:match);
        if (!isnull(cat)) cats[ncats++] = cat[1];
      }
    }

    # Get product ids for a given category.
    for (i=0; i< ncats; i++) {
      cat = cats[i];

      req = http_get(item:string(dir, "/viewCat_h.asp?idCategory=", cat), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = string("href='viewPrd.asp?idcategory=", cat, "&idproduct=([0-9]+)'>");
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          prod = eregmatch(pattern:pat, string:match);
          if (!isnull(prod)) {
            prod = prod[1];
            # nb: we only need to find 1 valid product id.      
            break;
          }
        }
      }

      # If we have a product id, try to exploit the flaw.
      if (prod) {
        req = http_get(
          item:string(
            dir, "/viewPrd.asp?",
            "idcategory=", cat, "'&",
            "idproduct=", prod
          ), 
          port:port
        );
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        # There's a problem if we see a syntax error.
        if (egrep(string:res, pattern:string("Syntax error.+'idcategory=", cat), icase:TRUE)) {
          security_warning(port);
          exit(0);
        }

        # We're not vulnerable, but we're finished checking this dir.
        break;
      }
    }
  }
}
