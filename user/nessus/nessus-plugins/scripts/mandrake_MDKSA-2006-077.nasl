#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:077
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21283);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
 
 name["english"] = "MDKSA-2006:077: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:077 (ethereal).



A number of vulnerabilities have been discovered in the Ethereal network
analyzer. These issues have been corrected in Ethereal version 0.99.0 which is
provided with this update.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:077
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.99.0-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.99.0-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.99.0-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.99.0-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1932", value:TRUE);
 set_kb_item(name:"CVE-2006-1933", value:TRUE);
 set_kb_item(name:"CVE-2006-1934", value:TRUE);
 set_kb_item(name:"CVE-2006-1935", value:TRUE);
 set_kb_item(name:"CVE-2006-1936", value:TRUE);
 set_kb_item(name:"CVE-2006-1937", value:TRUE);
 set_kb_item(name:"CVE-2006-1938", value:TRUE);
 set_kb_item(name:"CVE-2006-1939", value:TRUE);
 set_kb_item(name:"CVE-2006-1940", value:TRUE);
}
