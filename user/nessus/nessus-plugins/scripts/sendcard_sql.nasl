#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


if (description) {
  script_id(19748);
  script_cve_id("CVE-2005-2404");
  script_bugtraq_id(14351);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18153");
  }
  script_version("$Revision: 1.5 $");

  name["english"] = "Sendcard SQL injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Sendcard, a multi-database e-card program written 
in PHP.

The version of Sendcard installed on the remote host is prone to a SQL
injection attack due to its failure to sanitize user-supplied input to
the 'id' field in the 'sendcard.php' script. 

Solution : Unknown at this time
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection in the id field in sendcard.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005 Josh Zlatin-Amishav");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/sendcard.php?",
     "view=1&",
     "id=%27", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
       ( "SELECT \* FROM sendcard where id='" + SCRIPT_NAME) >< res  &&
         "MySQL Error" >< res
     ) 
  {
    security_note(port);
    exit(0);
  }
}
