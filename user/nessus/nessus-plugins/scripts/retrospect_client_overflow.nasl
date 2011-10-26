#
# (C) Tenable Network Security
#


if (description) {
  script_id(21327);
  script_cve_id("CVE-2006-2391");
  script_bugtraq_id(17948, 18064);
  script_version("$Revision: 1.6 $");

  script_name(english:"Retrospect Client Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of Retrospect client");

  desc = "
Synopsis :

It is possible to execute code on the remote backup client. 

Description :

According to its version number, the installed instance of Retrospect
client is vulnerable to a buffer overflow vulnerability when it receives
a packet starting with a specially-crafted sequence of bytes. 

An unauthenticated remote attacker may be able to exploit this flaw to
execute code on the remote host.

See also :

http://kb.dantz.com/display/2n/kb/article.asp?aid=9511&n=1&s=

Solution :

Upgrade to a newer version of Retrospect Client.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("retrospect_detect.nasl");
  script_require_ports("Services/retrospect", 497);

  exit(0);
}


port = get_kb_item("Services/retrospect");
if (!port) port = 497;
if (!get_port_state(port)) exit(0);


ver = get_kb_item(string("Retrospect/", port, "/Version"));
ostype = get_kb_item(string("Retrospect/", port, "/OSType"));
if (!ver || isnull(ostype))
  exit (0);

major = ostype >>> 16;
minor = ostype & 0xFFFF;
iver = split(ver, sep:'.', keep:FALSE);

# Windows
if (major > 1 && major < 10)
{
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 140) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 112) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 116)
  ) security_warning(port);
}

# Netware
if (major > 10)
{
  if (
    (int(iver[0]) == 1 && int(iver[1]) == 0 && int(iver[2]) < 141)
  ) security_warning(port);
}

# Unixes
if (major == 0)
{
 # Redhat
 if (minor == 0)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 112)
  ) security_warning(port);

 # Solaris
 if (minor == 1)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 109) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 112)
  ) security_warning(port);

 # Mac OS X
 if ((minor >> 8) == 0x10)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 0) ||
    (int(iver[0]) == 6 && int(iver[1]) == 1 && int(iver[2]) < 130)
  ) security_warning(port);
}

