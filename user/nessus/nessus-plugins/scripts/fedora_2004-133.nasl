#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13708);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0988");
 
 name["english"] = "Fedora Core 1 2004-133: kdepim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-133 (kdepim).

A PIM (Personal Information Manager) for KDE.


Update Information:


The KDE team found a buffer overflow in the file information reader of
VCF files. An attacker could construct a VCF file so that when it was
opened by a victim it would execute arbitrary commands. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2003-0988 to this issue.




Solution : http://www.fedoranews.org/updates/FEDORA-2004-133.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdepim package";
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
if ( rpm_check( reference:"kdepim-3.1.4-2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-debuginfo-3.1.4-2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-devel-3.1.4-2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdepim-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0988", value:TRUE);
}
