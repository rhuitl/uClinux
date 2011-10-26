#
# (C) Tenable Network Security
#


if (description) {
  script_id(21564);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-2369");
  script_bugtraq_id(17978);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25479");

  script_name(english:"RealVNC Authentication Bypass Vulnerability");
  script_summary(english:"Tries to bypass authentication using RealVNC");
 
  desc = "
Synopsis :

The remote VNC server is prone to an authentication bypass issue. 

Description :

The remote host appears to be running RealVNC, a VNC server for
Windows and Linux/unix platforms. 

The version of RealVNC installed on the remote host allows an attacker
to bypass authentication by simply requesting 'Type 1 - None' as the
authentication type even though it is not explicitly configured to
support that.  By exploiting this issue, an attacker gains access to
the affected host at the privilege level under which RealVNC operates,
typically as Administrator under Windows. 

See also :

http://www.intelliadmin.com/blog/2006/05/security-flaw-in-realvnc-411.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/046039.html
http://www.realvnc.com/products/free/4.1/release-notes.html
http://www.realvnc.com/products/personal/4.2/release-notes.html
http://www.realvnc.com/products/enterprise/4.2/release-notes.html

Solution :

Upgrade to RealVNC Free Edition 4.1.2 / Personal Edition 4.2.3 /
Enterprise Edition 4.2.3 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("vnc.nasl");
  script_require_ports("Services/vnc", 5900);

  exit(0);
}

include("byte_func.inc");

port = get_kb_item("Services/vnc");
if (!port) port = 5900;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

version = string ("RFB 003.008\n");

buf = recv (socket:soc, length:4096);
if (buf != version)
  exit (0);

send (socket:soc, data:version);

len = recv (socket:soc, length:1, min:1);
if (strlen(len) != 1)
  exit (0);

len = ord(len[0]);
types = recv (socket:soc, length:len, min:len);
if (strlen (types) != len)
  exit (0);

for (i=0; i< len; i++)
  if (ord(types[i]) == 1)
    exit (0);

send (socket:soc, data:mkbyte(1));
resp = recv (socket:soc, length:4, min:4);

if ((strlen(resp) == 4) && (getdword (blob:resp, pos:0) == 0))
  security_warning(port);
