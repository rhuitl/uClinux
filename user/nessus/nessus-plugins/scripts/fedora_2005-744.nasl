#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19469);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2101");
 
 name["english"] = "Fedora Core 4 2005-744: kdeedu";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-744 (kdeedu).

Educational/Edutainment applications for KDE

Update Information:

Ben Burton notified the KDE security team about several
tempfile handling related vulnerabilities in langen2kvtml,
a conversion script for kvoctrain. The script must be
manually invoked.

The script uses known filenames in /tmp which allow an local
attacker to overwrite files writeable by the user invoking the
conversion script.

This update fixes these vulnerabilities.


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_kdeedu-3.4.2-0.fc4.2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdeedu package";
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
if ( rpm_check( reference:"kdeedu-3.4.2-0.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdeedu-devel-3.4.2-0.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdeedu-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2101", value:TRUE);
}
