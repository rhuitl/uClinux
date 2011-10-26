#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:017
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21138);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:017: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:017 (sendmail).


The popular MTA sendmail is vulnerable to a race condition when handling
signals.
Under certain circumstances this bug can be exploited by an attacker to
execute commands remotely.

Sendmail was the default MTA in SuSE Linux Enterprise Server 8. Later
products use postfix as MTA.

Thanks to Mark Dowd who found this bug.


Solution : http://www.suse.de/security/advisories/2006_17_sendmail.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sendmail-8.13.4-8.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.11-2.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.13.1-5.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.13.3-5.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
