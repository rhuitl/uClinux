#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22902);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(20661);

  script_name(english:"Hosting Controller ForumID Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for a SQL injection flaw in Hosting Controller");
 
  desc = "
Synopsis :

The remote web server contains an ASP application that is susceptible
to a SQL injection attack. 

Description :

The installed version of Hosting Controller fails to sanitize input to
the 'ForumID' parameter of the 'forum/HCSpecific/EnableForum.asp'
script before using it in database queries.  An unauthenticated
attacker may be able to leverage this issue to manipulate database
queries to reveal sensitive information, modify data, launch attacks
against the underlying database, etc. 

See also :

http://www.kapda.ir/advisory-442.html

Solution :

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8077);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8077);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/hc", "/hosting_controller", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string("'", SCRIPT_NAME);
  req = http_get(
    item:string(
      dir, "/forum/HCSpecific/EnableForum.asp?",
      "action=enableforum&",
      "ForumID=", exploit
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    string("query expression 'ForumID='", SCRIPT_NAME) >< res &&
    egrep(pattern:"Microsoft OLE DB Provider for ODBC Drivers.+error '80040e14'", string:res)
  ) {
    security_hole(port);
    exit(0);
  }
}
