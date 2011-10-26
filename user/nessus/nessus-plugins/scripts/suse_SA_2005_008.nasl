#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17198);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0446");
 
 name["english"] = "SUSE-SA:2005:008: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:008 (squid).


Squid is an Open Source web proxy.

A remote attacker was potentially able to crash the Squid web proxy
if the log_fqdn option was set to 'on' and the DNS replies were
manipulated.

This is tracked by the Mitre CVE ID CVE-2005-0446.

This update also fixes a defect in the last security update patch
(CVE-2005-0241).



Solution : http://www.suse.de/security/advisories/2005_08_squid.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE1-108", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-120", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE5-42.30", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-6.8", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"SUSE8.2")
 || rpm_exists(rpm:"squid-", release:"SUSE9.0")
 || rpm_exists(rpm:"squid-", release:"SUSE9.1")
 || rpm_exists(rpm:"squid-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0446", value:TRUE);
}
