#
# (C) Tenable Network Security
#


if (description) {
  script_id(18525);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1951");
  script_bugtraq_id(13979);

  name["english"] = "osCommerce Multiple HTTP Response Splitting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to multiple HTTP Response splitting attacks. 

Description :

The remote host is running osCommerce, an open-source e-commerce
system. 

The version of osCommerce on the remote host suffers from multiple
HTTP response splitting vulnerabilities due to its failure to sanitize
user-supplied input to various parameters of the
'includes/application_top.php' script, the 'goto' parameter of the
'banner.php' script, and possibly others.  An attack can exploit these
flaws to inject malicious text into HTTP headers, possibly resulting
in the theft of session identifiers and/or misrepresentation of the
affected site. 

See also : 

http://www.gulftech.org/?node=research&article_id=00080-06102005
http://archives.neohapsis.com/archives/bugtraq/2005-06/0068.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple HTTP response splitting vulnerabilities in osCommerce";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

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
if (!can_host_php(port:port)) exit(0);


# Look for osCommerce.
foreach dir (cgi_dirs()) {
  # Request index.php.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like osCommerce...
  if (string(dir, "/index.php?osCsid") >< res) {
    # We need a valid product id for an exploit.
    pat = string(dir, "/product_info\\.php\\?products_id=([0-9]+)");
    matches = egrep(string:res, pattern:pat);
    foreach match (split(matches)) {
      match = chomp(match);
      prod = eregmatch(pattern:pat, string:match);
      if (!isnull(prod)) {
        prod = prod[1];

        # Try an exploit. A vulnerable application will output 
        # a redirect along with our own redirect.
        req = http_get(
          item:string(
            dir, "/index.php?",
            "action=buy_now&",
            "products_id=22=%0d%0aLocation:%20http://127.0.0.1/index.php?script=", SCRIPT_NAME
          ),
          port:port
        );
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
        if (res == NULL) exit(0);

        # There's a problem if we see a redirect with our script name.
        if (string("Location: http://127.0.0.1/index.php?script=", SCRIPT_NAME) >< res) {
          security_note(port);
          exit(0);
        }

        # We don't need to check any more products with this installation.
        break;
      }
    }
  }
}
