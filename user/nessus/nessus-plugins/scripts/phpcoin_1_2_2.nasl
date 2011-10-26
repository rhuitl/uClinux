#
# (C) Tenable Network Security
#


if (description) {
  script_id(18166);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1384");
  script_bugtraq_id(13433);

  name["english"] = "Multiple SQL Injection Vulnerabilities in phpCOIN <= 1.2.2";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
several SQL injection attacks. 

Description :

The remote host is running phpCOIN version 1.2.2 or older.  These
versions suffer from several SQL injection vulnerabilities due to
their failure to properly sanitize input to the 'search' parameter of
the 'index.php' script, the 'phpcoinsessid' parameter of the
'login.php' script and the 'id', 'dtopic_id', and 'dcat_id' parameters
of the 'mod.php' script before using it in SQL queries.  An attacker
may be able to exploit these flaws to alter database queries,
potentially revealing sensitive information or even modifying data.

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-04/0499.html
http://forums.phpcoin.com/index.php?showtopic=4607

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple SQL injection vulnerabilities in phpCOIN <= 1.2.2");

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
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through each directory with scripts.
foreach dir (cgi_dirs()) {

  # Try a couple of different ways to exploit the flaws.
  i = 0;
  # - POST request with SQL injection via 'id'.
  postdata = string(
    "mod=siteinfo&",
    "id=", SCRIPT_NAME, "'&",
    "phpcoinsessid=3ff9120788558adc3b6c8352d808c861"
  );
  exploits[i++] = string(
    "POST ", dir, "/mod.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  # - same as above but a GET request.
  exploits[i++] = http_get(item:string(dir, "/mod.php?", postdata), port:port);
  # - POST request with SQL injection via session id.
  postdata = string(
    "w=user&",
    "o=login&",
    "phpcoinsessid=", SCRIPT_NAME, "'"
  );
  exploits[i++] = string(
    "POST ", dir, "/login.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  # - same as above but a GET request.
  exploits[i++] = http_get(item:string(dir, "/login.php?", postdata), port:port);

  foreach exploit (exploits) {
    res = http_keepalive_send_recv(port:port, data:exploit);
    if (res == NULL) exit(0);

    # It's a problem if we see an error with our script name followed
    # by a single quote. This error message is hardcoded into 
    # db_query_execute() in coin_database/db_mysql.php.
    if (egrep(pattern:string("Unable to execute query: .+='", SCRIPT_NAME, "''"), string:res)) {
      security_warning(port);
      exit(0);
    }
  }
}
