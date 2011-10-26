#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a CGI application that is affected by a
privilege escalation issue. 

Description :

The remote host is running WebAdmin, a web-based remote administration
tool for Alt-N MDaemon. 

According to its banner, the installed version of WebAdmin enables a
domain administrator within the default domain to hijack the 'MDaemon'
account used by MDaemon when processing remote server and mailing list
commands. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-September/049247.html
http://files.altn.com/WebAdmin/Release/RelNotes_en.txt

Solution :

Upgrade to WebAdmin version 3.2.6 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:P/I:N/B:N)";


if (description) {
  script_id(22306);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(19841);
  script_xref(name:"OSVDB", value:"28548");

  script_name(english:"WebAdmin < 3.2.6 MDaemon Account Hijacking Vulnerability");
  script_summary(english:"Checks version of WebAdmin");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:1000);
if (!get_port_state(port)) exit(0);


# Get the version number from the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# There's a problem if ...
if (
  # it looks like WebAdmin and ...
  '<title>WebAdmin</title>' >< res &&
  '<form name="waForm" action="login.wdm"' >< res &&
  # it's version < 3.2.5
  egrep(pattern:">WebAdmin</A> v([0-2]\..*|3\.([01]\..*|2\.[0-5])) &copy;", string:res)
) security_note(port);
