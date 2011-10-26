#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:061
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14044);
 script_bugtraq_id(7497);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0255");
 
 name["english"] = "MDKSA-2003:061: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:061 (gnupg).


A bug was discovered in GnuPG versions 1.2.1 and earlier. When gpg evaluates
trust values for different UIDs assigned to a key, it would incorrectly
associate the trust value of the UID with the highest trust value with every
other UID assigned to that key. This prevents a warning message from being given
when attempting to encrypt to an invalid UID, but due to the bug, is accepted as
valid.
Patches have been applied for version 1.0.7 and all users are encouraged to
upgrade.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:061
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gnupg-1.0.7-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.0.7-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK8.2")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.0")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0255", value:TRUE);
}
