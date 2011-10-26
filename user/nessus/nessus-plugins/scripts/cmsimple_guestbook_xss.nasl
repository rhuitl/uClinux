#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


if (description) {
  script_id(19693);
  script_bugtraq_id(12303);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13130");
  }
  script_version("$Revision: 1.3 $");

  name["english"] = "CMSimple index.php guestbook XSS";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running CMSimple, a CMS written in PHP. 

The version of CMSimple installed on the remote host is prone to
cross-site scripting attacks due to its failure to sanitize
user-supplied input to both the search and guestbook modules. 

See also : http://securitytracker.com/alerts/2005/Jan/1012926.html
Solution : Upgrade to version 2.4 Beta 5 or higher.
Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for XSS in guestbook module in index.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"(C) 2005 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

if ( safe_checks() ) exit(0);

xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/index.php?",
     "guestbook=", exss, 
     "&function=guestbook",
     "&action=save"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (
    xss >< res &&
    (
      egrep(string:res, pattern:'meta name="generator" content="CMSimple .+ cmsimple\\.dk') ||
      egrep(string:res, pattern:'href="http://www\\.cmsimple\\.dk/".+>Powered by CMSimple<') ||
      egrep(string:res, pattern:string('href="', dir, '/\\?&(sitemap|print)">'))
    )
  ) 
  {
    security_note(port);
    exit(0);
  }
}
