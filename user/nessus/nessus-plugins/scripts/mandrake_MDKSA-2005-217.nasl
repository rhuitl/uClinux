#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:217
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20449);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3632", "CVE-2005-3662");
 
 name["english"] = "MDKSA-2005:217: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:217 (netpbm).



Greg Roelofs discovered and fixed several buffer overflows in pnmtopng which is
also included in netpbm, a collection of graphic conversion utilities, that can
lead to the execution of arbitrary code via a specially crafted PNM file.
Multiple buffer overflows in pnmtopng in netpbm 10.0 and earlier allow
attackers to execute arbitrary code via a crafted PNM file. (CVE-2005-3632) An
off-by-one buffer overflow in pnmtopng, when using the -alpha command line
option, allows attackers to cause a denial of service (crash) and possibly
execute arbitrary code via a crafted PNM file with exactly 256 colors.
(CVE-2005-3662) The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:217
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
if ( rpm_check( reference:"libnetpbm9-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-static-devel-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"netpbm-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-3632", value:TRUE);
 set_kb_item(name:"CVE-2005-3662", value:TRUE);
}
