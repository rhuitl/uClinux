#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19293);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1849");
 
 name["english"] = "Fedora Core 3 2005-625: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-625 (zlib).

Zlib is a general-purpose, patent-free, lossless data compression
library which is used by many different programs.


* Fri Jul 22 2005 Ivana Varekova 1.2.1.2-3.fc3
- fix bug 163038 - CVE-2005-1849 - zlib overflow problem



Solution : http://www.fedoranews.org/blog/index.php?p=784
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"zlib-1.2.1.2-3.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1.2-3.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-debuginfo-1.2.1.2-3.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"zlib-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
}
