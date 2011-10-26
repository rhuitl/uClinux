#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21607);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2437", "CVE-2006-2438");
  script_bugtraq_id(18007);

  script_name(english:"Resin viewfile Servlet File Disclosure Vulnerability");
  script_summary(english:"Tries to get the absolute installation path of Resin");
 
  desc = "
Synopsis :

The remote web server is prone to arbitrary file access. 

Description :

The remote host is running Resin, an application server. 

The installation of Resin on the remote host includes a servlet, named
'viewfile', that lets an unauthenticated remote attacker view any file
within the web root directory on the affected host, which may lead to
a loss of confidentiality. 

See also :

http://www.securityfocus.com/archive/1/434145/30/0/threaded
http://www.caucho.com/download/changes.xtp

Solution :

Remove the 'resin-doc.war' file and do not deploy using default
configuration files'; or upgrade to Resin 3.0.19 or later. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from Resin.
banner = get_http_banner(port:port);
if (!banner || "Resin/" >!< banner) exit(0);


# Try to exploit the issue to request a non-existent class file.
class = string("org/nessus/", SCRIPT_NAME, "/", unixtime(), ".class");
req = http_get(
  item:string(
    "/resin-doc/viewfile/?",
    "contextpath=/&",
    "servletpath=&",
    "file=WEB-INF/classes/", class
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we get an error involving our class name with a full path.
#
# nb: 3.0.19 returns something like:
#     <b>File not found /WEB-INF/classes/org/nessus/resin_viewfile_file_access.nasl/1147831042.class</b></font>
if (
  "<b>File not found" &&
  egrep(pattern:string("found /.+/webapps/ROOT/WEB-INF/classes/", class, "<"), string:res)
) security_note(port);
