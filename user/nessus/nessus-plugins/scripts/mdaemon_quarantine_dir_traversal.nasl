#
# (C) Tenable Network Security
#


if (description) {
  script_id(19310);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(14400);

  name["english"] = "MDaemon Content Filter Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server is prone to directory traversal attacks. 

Description :

The remote host is running Alt-N MDaemon, an SMTP/IMAP server for
Windows. 

According to its banner, the version of MDaemon on the remote host is
prone to a directory traversal flaw that can be exploited to overwrite
files outside the application's quarantine directory provided
MDaemon's attachment quarantine feature is enabled. 

See also :

http://secunia.com/advisories/16173/
http://files.altn.com/MDaemon/Release/RelNotes_en.txt

Solution : 

Upgrade to MDaemon version 8.1.0 or later.

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for content filter directory traversal vulnerability in MDaemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap")) exit(0);


# Check the version number in the banner.
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(string:banner, pattern:"^\* OK .*IMAP4rev1 MDaemon ([0-7]\..+|8\.0\..+) ready")
) {
  security_hole(port);
  exit(0);
}
