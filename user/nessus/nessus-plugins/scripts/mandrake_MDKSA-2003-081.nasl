#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:081
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14063);
 script_bugtraq_id(8361, 8362);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0468", "CVE-2003-0540");
 
 name["english"] = "MDKSA-2003:081: postfix";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:081 (postfix).


Two vulnerabilities were discovered in the postfix MTA by Michal Zalewski.
Versions prior to 1.1.12 would allow an attacker to bounce- scan private
networks or use the daemon as a DDoS (Distributed Denial of Service) tool by
forcing the daemon to connect to an arbitrary service at an arbitrary IP address
and receiving either a bounce message or by timing. As well, versions prior to
1.1.12 have a bug where a malformed envelope address can cause the queue manager
to lock up until an entry is removed from the queue and also lock up the SMTP
listener leading to a DoS.
Postfix version 1.1.13 corrects these issues. The provided packages have been
patched to fix the vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:081
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postfix package";
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
if ( rpm_check( reference:"postfix-20010228-20.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-1.1.13-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"postfix-", release:"MDK8.2")
 || rpm_exists(rpm:"postfix-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0468", value:TRUE);
 set_kb_item(name:"CVE-2003-0540", value:TRUE);
}
