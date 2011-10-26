#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:083
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14332);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0792");
 
 name["english"] = "MDKSA-2004:083: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:083 (rsync).


An advisory was sent out by the rsync team regarding a security vulnerability in
all versions of rsync prior to and including 2.6.2. If rsync is running in
daemon mode, and not in a chrooted environment, it is possible for a remote
attacker to trick rsyncd into creating an absolute pathname while sanitizing it.
This vulnerability allows a remote attacker to possibly read/write to/from files
outside of the rsync directory.
The updated packages are patched to prevent this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:083
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync package";
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
if ( rpm_check( reference:"rsync-2.6.0-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK10.0")
 || rpm_exists(rpm:"rsync-", release:"MDK9.1")
 || rpm_exists(rpm:"rsync-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0792", value:TRUE);
}
