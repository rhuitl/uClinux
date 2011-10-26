#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:099-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21715);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661");
 
 name["english"] = "MDKSA-2006:099-1: freetype2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:099-1 (freetype2).



Integer underflow in Freetype before 2.2 allows remote attackers to cause

a denial of service (crash) via a font file with an odd number of blue

values, which causes the underflow when decrementing by 2 in a context

that assumes an even number of values. (CVE-2006-0747)



Multiple integer overflows in FreeType before 2.2 allow remote attackers to

cause a denial of service (crash) and possibly execute arbitrary code via

attack vectors related to (1) bdf/bdflib.c, (2) sfnt/ttcmap.c,

(3) cff/cffgload.c, and (4) the read_lwfn function and a crafted LWFN file

in base/ftmac.c. (CVE-2006-1861)



Ftutil.c in Freetype before 2.2 allows remote attackers to cause a denial

of service (crash) via a crafted font file that triggers a null dereference.

(CVE-2006-2661)



In addition, a patch is applied to 2.1.10 in Mandriva 2006 to fix a serious

bug in ttkern.c that caused some programs to go into an infinite loop when

dealing with fonts that don't have a properly sorted kerning sub-table.

This patch is not applicable to the earlier Mandriva releases.



Update:



The previous update introduced some issues with other applications and

libraries linked to libfreetype, that were missed in testing for the

vulnerabilty issues. The new packages correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:099-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freetype2 package";
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
if ( rpm_check( reference:"libfreetype6-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"freetype2-", release:"MDK10.2")
 || rpm_exists(rpm:"freetype2-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0747", value:TRUE);
 set_kb_item(name:"CVE-2006-1861", value:TRUE);
 set_kb_item(name:"CVE-2006-2661", value:TRUE);
}
