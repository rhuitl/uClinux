#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a CGI application that is affected by
multiple issues. 

Description :

The remote host is running WebAdmin, a web-based remote administration
tool for Alt-N MDaemon. 

According to its banner, the installed version of WebAdmin fails to
properly filter directory traversal sequences from the 'file'
parameter of the 'logfile_view.wdm' and 'configfile_view.wdm' scripts. 
A global administrator can leverage this issue to read and write to
arbitrary files on the affected host, subject to the privileges of the
web server user id, which in the case WebAdmin's internal web server
is used, is LOCAL SYSTEM. 

In addition, the affected application also reportedly allows a domain
administrator to edit the account of a global administrator, which can
be leveraged to login as the global administrator by changing his
password. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-August/048959.html
http://lists.altn.com/WebX?50@813.igqdaKNhCRb.0@.eeb9cff

Solution :

Upgrade to WebAdmin 3.2.5 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(22257);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4370", "CVE-2006-4371");
  script_bugtraq_id(19620, 19631);
  script_xref(name:"OSVDB", value:"28122");
  script_xref(name:"OSVDB", value:"28123");

  script_name(english:"WebAdmin < 3.2.5 Multiple Vulnerabilities");
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
  egrep(pattern:">WebAdmin</A> v([0-2]\..*|3\.([01]\..*|2\.[0-4])) &copy;", string:res)
) security_warning(port);
