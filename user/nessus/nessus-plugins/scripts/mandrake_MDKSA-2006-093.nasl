#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:093
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21617);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2453", "CVE-2006-2480");
 
 name["english"] = "MDKSA-2006:093: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:093 (dia).



A format string vulnerability in Dia allows user-complicit

attackers to cause a denial of service (crash) and possibly execute

arbitrary code by triggering errors or warnings, as demonstrated via

format string specifiers in a .bmp filename. NOTE: the original

exploit was demonstrated through a command line argument, but there

are other mechanisms inputs that are automatically process by Dia,

such as a crafted .dia file. (CVE-2006-2480)



Multiple unspecified format string vulnerabilities in Dia have

unspecified impact and attack vectors, a different set of issues

than CVE-2006-2480. (CVE-2006-2453)



Packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:093
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia package";
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
if ( rpm_check( reference:"dia-0.94-6.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dia-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2453", value:TRUE);
 set_kb_item(name:"CVE-2006-2480", value:TRUE);
}
