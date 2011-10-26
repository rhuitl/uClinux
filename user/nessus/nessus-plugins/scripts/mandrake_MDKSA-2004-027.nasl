#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14126);
 script_bugtraq_id(10072);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0155");
 
 name["english"] = "MDKSA-2004:027: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:027 (ipsec-tools).


A very serious security flaw was discovered by Ralf Spenneberg in racoon, the
IKE daemon of the KAME-tools. Racoon does not very the RSA signature during
phase one of a connection using either main or aggressive mode. Only the
certificate of the client is verified, the certificate is not used to verify the
client's signature.
All versions of ipsec-tools prior to 0.2.5 and 0.3rc5 are vulnerable to this
issue. The provided package updates ipsec-tools to 0.2.5.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:027
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec-tools0-0.2.5-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0155", value:TRUE);
}
