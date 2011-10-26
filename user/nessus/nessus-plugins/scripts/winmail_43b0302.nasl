#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21223);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1250");
  script_bugtraq_id(17009);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23877");

  script_name(english:"Winmail Server Unspecified Webmail Vulnerability");
  script_summary(english:"Checks version of Winmail Server");

  desc = "
Synopsis :

The remote webmail server is affected by an unspecified issue. 

Description :

The remote host is running Winmail Server, a commercial mail server
for Windows from AMAX Information Technologies.

According to its version number, the remote installation of Winmail
Server is affected by an unknown issue in its webmail component. It
is unclear whether this is the same issue identified by Secunia in 
November 2005 and covered by Bugtraq ID 15493.

See also : 

http://www.magicwinmail.net/changelog.asp

Solution : 

Upgrade to Winmail Server 4.3(Build 0302) or later. 

Risk factor : 

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:6080);
if (!get_port_state(port)) exit(0);


# Get the version number from the webmail server's banner.
res = http_get_cache(item:"/", port:port);
if (
  res && 
  "Winmail Server Webmail bases on the UebiMiau." &&
  egrep(pattern:"WebMail \| Powered by Winmail Server ([0-3]\.|4\.[0-2])", string:res)
) security_warning(port);
