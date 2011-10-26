#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13697);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0234", "CVE-2004-0235");
 
 name["english"] = "Fedora Core 1 2004-119: lha";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-119 (lha).

LHA is an archiving and compression utility for LHarc format archives.
LHA is mostly used in the DOS world, but can be used under Linux to
extract DOS files from LHA archives.

Install the lha package if you need to extract DOS files from LHA archives.

Update Information:


Ulf Härnhammar discovered two stack buffer overflows and two directory
traversal flaws in LHA. An attacker could exploit the buffer
overflows by creating a carefully crafted LHA archive in such a way
that arbitrary code would be executed when the archive is tested or
extracted by a victim. CVE-2004-0234. An attacker could exploit the
directory traversal issues to create files as the victim outside of
the expected directory. CVE-2004-0235.




Solution : http://www.fedoranews.org/updates/FEDORA-2004-119.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lha package";
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
if ( rpm_check( reference:"lha-1.14i-12.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lha-debuginfo-1.14i-12.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lha-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0234", value:TRUE);
 set_kb_item(name:"CVE-2004-0235", value:TRUE);
}
