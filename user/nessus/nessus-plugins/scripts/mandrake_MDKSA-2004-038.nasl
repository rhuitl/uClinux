#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:038
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14137);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:038: sysklogd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:038 (sysklogd).


Steve Grubb discovered a bug in sysklogd where it allocates an insufficient
amount of memory which causes sysklogd to write to unallocated memory. This
could allow for a malicious user to crash sysklogd.
The updated packages provide a patched sysklogd using patches from Openwall to
correct the problem and also corrects the use of an unitialized variable (a
previous use of 'count').


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:038
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sysklogd package";
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
if ( rpm_check( reference:"sysklogd-1.4.1-5.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sysklogd-1.4.1-5.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sysklogd-1.4.1-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
