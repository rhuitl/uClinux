#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14168);
 script_bugtraq_id(10172);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0403");
 
 name["english"] = "MDKSA-2004:069: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:069 (ipsec-tools).


A vulnerability in racoon prior to version 20040408a would allow a remote
attacker to cause a DoS (memory consumption) via an ISAKMP packet with a large
length field.
Another vulnerability in racoon was discovered where, when using RSA signatures,
racoon would validate the X.509 certificate but would not validate the
signature. This can be exploited by an attacker sending a valid and trusted
X.509 certificate and any private key. Using this, they could perform a
man-in-the-middle attack and initiate an unauthorized connection. This has been
fixed in ipsec-tools 0.3.3.
The updated packages contain patches backported from 0.3.3 to correct the
problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:069
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools package";
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec-tools0-0.2.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0403", value:TRUE);
}
