#
# (C) Tenable Network Security
#


if (description) {
  script_id(20754);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0319");
  script_bugtraq_id(16321);

  script_name(english:"Farmers WIFE FTP Server Directory Traversal Vulnerability");
  script_summary(english:"Checks for directory traversal vulnerability in Farmers WIFE FTP server");
 
  desc = "
Synopsis :

The remote ftp server is affected by a directory traversal flaw. 

Description :

The remote host appears to be running Farmers WIFE, a commercial
facilities, scheduling, and asset management package targeted at the
media industry. 

The version of Farmers WIFE installed on the remote host includes an
FTP server that reportedly is vulnerable to directory traversal
attacks.  A user can leverage this issue to read and write to files
outside the ftp root.  Note that the application runs with SYSTEM
privileges under Windows. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041356.html

Solution :

Upgrade to Farmers WIFE 4.4 SP3 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/ftp", 22003, "Services/www", 22002);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


ftp_port = get_kb_item("Services/ftp");
if (!ftp_port) ftp_port = 22003;
if (!get_port_state(ftp_port)) exit(0);
http_port = get_http_port(default:22002);
if (!get_port_state(http_port)) exit(0);


# Get the initial page.
res = http_get_cache(item:"/", port:http_port);
if (res == NULL) exit(0);


# There's a problem if the version appears to be less than 4.4 SP3.
if (
  "<title>Farmers WIFE Web</title>" >< res &&
  egrep(pattern:">Server Version: ([0-3]\..+|4\.([0-3].*|4( \(sp[0-2]\)))?) &nbsp;", string:res)
) {
  security_note(ftp_port);
  exit(0);
}
