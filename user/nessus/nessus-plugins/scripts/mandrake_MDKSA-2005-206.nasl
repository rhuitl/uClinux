#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:206-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20440);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3393", "CVE-2005-3409");
 
 name["english"] = "MDKSA-2005:206-1: openvpn";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:206-1 (openvpn).



Two Denial of Service vulnerabilities exist in OpenVPN. The first allows a
malicious or compromised server to execute arbitrary code on the client
(CVE-2005-3393). The second DoS can occur if when in TCP server mode, OpenVPN
received an error on accept(2) and the resulting exception handler causes a
segfault (CVE-2005-3409). The updated packages have been patched to correct
these problems.

Update:

Packages are now available for Mandriva Linux 2006.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:206-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openvpn package";
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
if ( rpm_check( reference:"openvpn-2.0.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openvpn-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3393", value:TRUE);
 set_kb_item(name:"CVE-2005-3409", value:TRUE);
}
