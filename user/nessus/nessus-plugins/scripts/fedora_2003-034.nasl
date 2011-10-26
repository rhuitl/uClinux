#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13667);
 script_bugtraq_id(9210);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0963");
 
 name["english"] = "Fedora Core 1 2003-034: lftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-034 (lftp).

LFTP is a sophisticated ftp/http file transfer program. Like bash, it
has job control and uses the readline library for input. It has
bookmarks, built-in mirroring, and can transfer several files in
parallel. It is designed with reliability in mind.


Update Information:

Ulf Härnhammar found a remotely-triggerable buffer overflow in lftp.

An attacker could create a carefully crafted directory on a website
such that, if a user connects to that directory using the lftp client
and subsequently issues a 'ls' or 'rels' command, the attacker could
execute arbitrary code on the users machine. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2003-0963 to this issue.

Users of lftp are advised to upgrade to these erratum packages, which
upgrade lftp to a version which is not vulnerable to this issue.

Red Hat would like to thank Ulf Härnhammar for discovering and
alerting us to this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2003-034.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lftp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lftp-2.6.10-1", prefix:"lftp-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lftp-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0963", value:TRUE);
}
