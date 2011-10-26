#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19481);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2499");
 
 name["english"] = "Fedora Core 3 2005-771: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-771 (slocate).

Slocate is a security-enhanced version of locate. Just like locate,
slocate searches through a central database (which is updated nightly)
for files that match a given pattern. Slocate allows you to quickly
find files anywhere on your system.

Update Information:

A carefully prepared directory structure could stop the
updatedb file system scan, resulting in an incomplete slocate
database. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2499 to this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=849
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the slocate package";
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
if ( rpm_check( reference:"slocate-2.7-12.fc3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-debuginfo-2.7-12.fc3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"slocate-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2499", value:TRUE);
}
