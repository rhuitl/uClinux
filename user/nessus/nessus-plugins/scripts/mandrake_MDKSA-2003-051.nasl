#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:051
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14035);
 script_bugtraq_id(7050);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0081", "CVE-2003-0159");
 
 name["english"] = "MDKSA-2003:051: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:051 (ethereal).


A vulnerability was discovered in Ethereal 0.9.9 and earlier that allows a
remote attacker to use specially crafted SOCKS packets to cause a denial of
service (DoS) and possibly execute arbitrary code.
A similar vulnerability also exists in the NTLMSSP code in Ethereal 0.9.9 and
earlier, due to a heap-based buffer overflow.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:051
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.9.11-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0081", value:TRUE);
 set_kb_item(name:"CVE-2003-0159", value:TRUE);
}
