#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11195);
  if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0001");
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");

  name["english"] = "SSH Multiple Vulns";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host

Description :

According to its banner, the remote SSH server is vulnerable to one or 
more of the following vulnerabilities:

- CVE-2002-1357 (incorrect length)
- CVE-2002-1358 (lists with empty elements/empty strings)
- CVE-2002-1359 (large packets and large fields)
- CVE-2002-1360 (string fields with zeros)

Some of these vulnerabilities may allow remote attackers to execute 
arbitrary code with the privileges of the SSH process, usually root.

Solution : 

Upgrade your SSH server to an unaffected version

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

  script_description(english:desc["english"]);

  summary["english"] = "SSH Multiple Vulnerabilities 16/12/2002";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
  script_family(english:"Gain root remotely");
  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");

  exit(0);
}

#
# The script code starts here
#
include("backport.inc");
port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);


banner = get_backport_banner(banner:banner);


#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_hole(port);
}

#
# SSH-2.0-3.2.0 SSH Secure Shell Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) SSH Secure Shell", string:banner, icase:TRUE))
{ 
  security_hole(port);
}

#
# SSH-1.99-Pragma SecureShell 3.0
# versions up to 2.* affected
#
if(ereg(pattern:"^SSH-1.99-Pragma SecureShell ([12]\..*)", string:banner, icase:TRUE))
{ 
  security_hole(port);
}
