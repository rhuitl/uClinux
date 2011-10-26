#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:088
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21599);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2213");
 
 name["english"] = "MDKSA-2006:088: hostapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:088 (hostapd).



Hostapd 0.3.7 allows remote attackers to cause a denial of service

(segmentation fault) via an unspecified value in the key_data_length

field of an EAPoL frame.



Packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:088
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hostapd package";
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
if ( rpm_check( reference:"hostapd-0.3.7-2.1.102dk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hostapd-0.3.7-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hostapd-", release:"MDK10.2")
 || rpm_exists(rpm:"hostapd-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2213", value:TRUE);
}
