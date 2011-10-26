#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:043
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15923);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013");
 
 name["english"] = "SUSE-SA:2004:043: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:043 (cyrus-imapd).


Stefan Esser reported various bugs within the Cyrus IMAP Server.
These include buffer overflows and out-of-bounds memory access
which could allow remote attackers to execute arbitrary commands
as root. The bugs occur in the pre-authentication phase, therefore
an update is strongly recommended.



Solution : http://www.suse.de/security/2004_43_cyrus_imapd.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-imapd-2.1.16-56", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.12-75", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.15-89", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.3-83.19", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-6.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-imapd-", release:"SUSE8.1")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE8.2")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.0")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.1")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1011", value:TRUE);
 set_kb_item(name:"CVE-2004-1012", value:TRUE);
 set_kb_item(name:"CVE-2004-1013", value:TRUE);
}
