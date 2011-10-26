#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:013
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17271);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0373");
 
 name["english"] = "SUSE-SA:2005:013: cyrus-sasl,cyrus-sasl2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:013 (cyrus-sasl,cyrus-sasl2).


cyrus-sasl is a library providing authentication services.

A buffer overflow in the digestmda5 code was identified that could lead
to a remote attacker executing code in the context of the service using
sasl authentication.

This is tracked by the Mitre CVE ID CVE-2005-0373.


Solution : http://www.suse.de/security/advisories/2005_13_cyrus_sasl.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl,cyrus-sasl2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-sasl2-2.1.12-66", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.15-109", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.18-33.8", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-sasl-", release:"SUSE8.2")
 || rpm_exists(rpm:"cyrus-sasl-", release:"SUSE9.0")
 || rpm_exists(rpm:"cyrus-sasl-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2005-0373", value:TRUE);
}
