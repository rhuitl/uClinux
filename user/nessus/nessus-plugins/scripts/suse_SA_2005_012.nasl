#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:012
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17242);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0198");
 
 name["english"] = "SUSE-SA:2005:012: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:012 (imap).


The University of Washington imap daemon can be used to access mails
remotely using the IMAP protocol.

This update fixes a logical error in the challenge response
authentication mechanism CRAM-MD5 used by UW IMAP. Due to this
mistake a remote attacker can gain access to the IMAP server as
arbitrary user.

This is tracked by the Mitre CVE ID CVE-2005-0198.


Solution : http://www.suse.de/security/advisories/2005_12_imap.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imap package";
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
if ( rpm_check( reference:"imap-2002-56", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2002d-59", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2002e-92.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2004a-3.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"imap-", release:"SUSE8.2")
 || rpm_exists(rpm:"imap-", release:"SUSE9.0")
 || rpm_exists(rpm:"imap-", release:"SUSE9.1")
 || rpm_exists(rpm:"imap-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0198", value:TRUE);
}
