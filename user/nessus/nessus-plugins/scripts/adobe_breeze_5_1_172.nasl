#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to a directory traversal attack. 

Description :

The remote web server appears to be Adobe Breeze, a web-based video
conferencing system. 

The version of Adobe Breeze installed on the remote host reportedly
has an issue with URL parsing.  While specific information about the
issue are currently not publically known, a remote attacker may be
able to exploit this to view arbitrary files on the affected host. 

See also :

http://www.adobe.com/support/security/bulletins/apsb06-16.html

Solution :

Upgrade as necessary to Breeze 5.1 SP2 and install the patch as
described in the vendor advisory referenced above. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(22868);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-5200");
  script_bugtraq_id(20438);

  script_name(english:"Adobe Breeze Directory Traversal Vulnerability");
  script_summary(english:"Checks version of Adobe Breeze");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from JRun.
banner = get_http_banner(port:port);
if (!banner || "Server: JRun Web Server" >!< banner) exit(0);


# Grab version information and make sure it's Breeze.
req = http_get(item:"/version.txt", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);
if ('Set-Cookie: BREEZESESSION=' >!< res) exit(0);


# Extract the version info.
v_min = NULL;
r = NULL;
pat = '^5\\.([0-9]),([0-9]+)';
matches = egrep(pattern:pat, string:res);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      v_min = int(ver[1]);
      r = int(ver[2]);
      break;
    }
  }
}
if (isnull(v_min) || isnull(r)) exit(0);


# There's a problem if it's [5.0, 5.1 r 172).
if (v_min == 0 || (v_min == 1 && r < 172))
{
  if (report_verbosity > 1)
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined that the installed version of Breeze is :\n",
      "  5.", v_min, " r. ", r
    );
  else report = desc;

  security_note(port:port, data:report);
  exit(0);
}
