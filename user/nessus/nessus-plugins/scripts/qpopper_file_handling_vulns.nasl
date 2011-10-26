#
# (C) Tenable Network Security
#


if (description) {
  script_id(18361);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1151", "CVE-2005-1152");
  script_bugtraq_id(13714);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"16811");

  name["english"] = "Qpopper Insecure File Handling Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote POP3 server is affected by multiple file handling flaws. 

Description :

According to its banner, the remote host is running a version of the
Qpopper POP3 server that suffers from two local, insecure file
handling vulnerabilities.  First, it fails to properly drop root
privileges when processing certain local files, which could lead to
overwriting or creation of arbitrary files as root.  And second, it
fails to set the process umask, potentially allowing creation of
group- or world-writable files. 

See also : 

http://bugs.gentoo.org/show_bug.cgi?id=90622
http://www.mail-archive.com/qpopper@lists.pensive.org/msg05140.html

Solution : 

Upgrade to Qpopper 4.0.6 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for insecure file handling vulnerabilities in Qpopper";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");

  exit(0);
}

include("global_settings.inc");
include("pop3_func.inc");


if (report_paranoia < 1) exit(0);	# FP on debian


if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# There's a problem if the banner indicates version 4.0.5 or earlier.
banner = get_pop3_banner(port:port);
if (
  banner &&
  " QPOP " >< banner &&
  banner =~ " QPOP \(version ([0-3]\..*|4\.0\.[0-5])$"
) security_hole(port);
