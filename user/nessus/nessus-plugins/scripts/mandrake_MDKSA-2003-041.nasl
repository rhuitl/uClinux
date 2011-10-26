#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:041-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14025);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(7120);
 script_cve_id("CVE-2003-0140");
 
 name["english"] = "MDKSA-2003:041-1: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:041-1 (mutt).


A vulnerability was discovered in the mutt text-mode email client in the IMAP
code. This vulnerability can be exploited by a malicious IMAP server to crash
mutt or even execute arbitrary code with the privilege of the user running mutt.
Update:
The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed. This has
been fixed and as a result the md5sums have changed. Thanks to Mark Lyda for
pointing this out.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:041-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.4.1i-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0140", value:TRUE);
}
