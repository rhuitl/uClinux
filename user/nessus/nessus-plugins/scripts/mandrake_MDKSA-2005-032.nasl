#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:032-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16375);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-1999-1572");
 
 name["english"] = "MDKSA-2005:032-1: cpio";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:032-1 (cpio).



A vulnerability in cpio was discovered where cpio would create world- writeable
files when used in -o/--create mode and giving an output file (with -O). This
would allow any user to modify the created cpio archive. The updated packages
have been patched so that cpio now respects the current umask setting of the
user.

Update:

The updated cpio packages for 10.1, while they would install with urpmi on the
commandline, would not install via rpmdrake. The updated packages correct that.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:032-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cpio package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cpio-2.5-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-1999-1572", value:TRUE);
}
