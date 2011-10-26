#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19480);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2499");
 
 name["english"] = "Fedora Core 4 2005-770: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-770 (slocate).

Slocate is a security-enhanced version of locate. Just like locate,
slocate searches through a central database (which is updated nightly)
for files that match a given pattern. Slocate allows you to quickly
find files anywhere on your system.

Update Information:

A carefully prepared directory structure could stop the
updatedb file system scan, resulting in an incomplete slocate
database. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2499 to this issue.



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_slocate-2.7-22.fc4.1
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
if ( rpm_check( reference:"slocate-2.7-22.fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"slocate-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2499", value:TRUE);
}
