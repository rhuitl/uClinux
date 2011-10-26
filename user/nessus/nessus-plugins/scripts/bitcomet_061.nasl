#
#  (C) Tenable Network Security
#


if (description) {
  script_id(20749);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0339");
  script_bugtraq_id(16311);
  script_xref(name:"OSVDB", value:"22625");

  script_name(english:"BitComet URI buffer Overflow Vulnerability");
  script_summary(english:"Checks for URI buffer overflow vulnerability in BitComet"); 
 
 desc = "
Synopsis :

The remote Windows host has a peer-to-peer application that is
affected by a remote buffer overflow vulnerability. 

Description :

The version of BitComet installed on the remote Windows host has a
buffer overflow flaw that could be triggered using a .torrent with a
specially-crafted publisher's name to crash the application or even
execute arbitrary code remotely subject to the user's privileges. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041558.html
http://www.bitcomet.com/doc/changelog.htm

Solution :

Upgrade to BitComet 0.61 or later, or remove the application. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("bitcomet_installed.nasl");
  script_require_keys("SMB/BitComet/Version");

  exit(0);
}


# Check version of BitComet.
ver = get_kb_item("SMB/BitComet/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  if (int(iver[0]) == 0 && int(iver[1]) < 61) security_warning(get_kb_item("SMB/transport"));
}
