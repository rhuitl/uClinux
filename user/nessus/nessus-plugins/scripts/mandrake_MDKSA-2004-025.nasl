#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14124);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0189");
 
 name["english"] = "MDKSA-2004:025: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:025 (squid).


A vulnerability was discovered in squid version 2.5.STABLE4 and earlier with the
processing of %-encoded characters in a URL. If a squid configuration uses ACLs
(Access Control Lists), it is possible for a remote attacker to create URLs that
would not be properly tested against squid's ACLs, potentially allowing clients
to access URLs that would otherwise be disallowed.
As well, the provided packages for Mandrake Linux 9.2 and 9.1 include a new
Access Control type called 'urllogin' which can be used to protect vulnerable
Microsoft Internet Explorer clients from accessing URLs that contain login
information. While this Access Control type is available, it is not used in the
default configuration.
The updated packages are patched to protect against these vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:025
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE4-1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE1-7.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK9.1")
 || rpm_exists(rpm:"squid-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0189", value:TRUE);
}
