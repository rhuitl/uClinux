#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:052
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13955);
 script_bugtraq_id(4742);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0178");
 
 name["english"] = "MDKSA-2002:052: sharutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:052 (sharutils).


The uudecode utility creates output files without checking to see if it is about
to write to a symlink or pipe. This could be exploited by a local attacker to
overwrite files or lead to privilege escalation if users decode data into share
directories, such as /tmp. This update fixes this vulnerability by checking to
see if the destination output file is a symlink or pipe.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:052
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sharutils package";
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
if ( rpm_check( reference:"sharutils-4.2.1-8.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-8.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sharutils-", release:"MDK7.1")
 || rpm_exists(rpm:"sharutils-", release:"MDK7.2")
 || rpm_exists(rpm:"sharutils-", release:"MDK8.0")
 || rpm_exists(rpm:"sharutils-", release:"MDK8.1")
 || rpm_exists(rpm:"sharutils-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0178", value:TRUE);
}
