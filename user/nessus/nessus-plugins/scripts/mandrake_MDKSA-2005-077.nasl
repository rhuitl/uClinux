#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:077
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18107);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0866");
 
 name["english"] = "MDKSA-2005:077: cdrecord";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:077 (cdrecord).



Javier Fernandez-Sanguino Pena discovered that cdrecord created temporary files
in an insecure manner if DEBUG was enabled in /etc/cdrecord/rscsi. If the
default value was used (which stored the debug output file in /tmp), a symbolic
link attack could be used to create or overwrite arbitrary files with the
privileges of the user invoking cdrecord. Please note that by default this
configuration file does not exist in Mandriva Linux so unless you create it and
enable DEBUG, this does not affect you.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:077
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cdrecord package";
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
if ( rpm_check( reference:"cdrecord-2.01-0.a28.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-2.01-0.a28.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01-0.a28.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01-0.a28.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-isotools-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-vanilla-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-isotools-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-vanilla-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01.01-0.a01.6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cdrecord-", release:"MDK10.0")
 || rpm_exists(rpm:"cdrecord-", release:"MDK10.1")
 || rpm_exists(rpm:"cdrecord-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0866", value:TRUE);
}
