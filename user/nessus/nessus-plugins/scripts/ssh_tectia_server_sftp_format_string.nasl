#
# (C) Tenable Network Security
#


if (description) {
  script_id(20927);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0705");
  script_bugtraq_id(16640);

  script_name(english:"SSH Tectia Server SFTP Format String Vulnerability");
  script_summary(english:"Checks for format string vulnerability in SSH Tectia Server SFTP subsystem");
 
  desc = "
Synopsis :

The remote SSH server may be affected by a format string
vulnerability. 

Description :

The remote host is running SSH Tectia Server, a commercial SSH server. 

According to its banner, the installed version of this software
contains a format string vulnerability in its sftp subsystem.  A
remote, authenticated attacker may be able to execute arbitrary code
on the affected host subject to his privileges or crash the server
itself. 

See also :

http://www.ssh.com/company/newsroom/article/715/

Solution :

As a temporary solution, disable the sftp subsystem as described in
the vendor advisory above.  A better solution, though, is to upgrade
to SSH Tectia Server version 4.3.7 or 4.4.2 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");

port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = get_backport_banner(banner:banner);

if ( ereg(pattern:"^SSH-2\.0-([0-3]\..*|4\.([0-2]\..*|3\.[0-6]\..*|4\.[01]\..*)) SSH (Tectia Server|Secure Shell)", string:banner)
) {
  security_note(port);
}
