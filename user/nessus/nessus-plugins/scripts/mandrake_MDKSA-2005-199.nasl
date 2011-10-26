#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:199
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20437);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2978");
 
 name["english"] = "MDKSA-2005:199: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:199 (netpbm).



Pnmtopng in netpbm 10.2X, when using the -trans option, uses uninitialized size
and index variables when converting Portable Anymap (PNM) images to Portable
Network Graphics (PNG), which might allow attackers to execute arbitrary code
by modifying the stack. Netpbm 9.2X is not affected by this vulnerability. The
updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:199
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libnetpbm10-10.26-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm10-devel-10.26-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm10-static-devel-10.26-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-10.26-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm10-10.29-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm10-devel-10.29-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm10-static-devel-10.29-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-10.29-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"netpbm-", release:"MDK10.2")
 || rpm_exists(rpm:"netpbm-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2978", value:TRUE);
}
