#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:013
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14113);
 script_bugtraq_id(9336);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0965", "CVE-2003-0991", "CVE-2003-0992");
 
 name["english"] = "MDKSA-2004:013: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:013 (mailman).


A cross-site scripting vulnerability was discovered in mailman's administration
interface (CVE-2003-0965). This affects version 2.1 earlier than 2.1.4.
Certain malformed email commands could cause the mailman process to crash.
(CVE-2003-0991). This affects version 2.0 earler than 2.0.14.
Another cross-site scripting vulnerability was found in mailman's 'create' CGI
script (CVE-2003-0992). This affects version 2.1 earlier than 2.1.3.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:013
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.0.14-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.2-9.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK9.1")
 || rpm_exists(rpm:"mailman-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0965", value:TRUE);
 set_kb_item(name:"CVE-2003-0991", value:TRUE);
 set_kb_item(name:"CVE-2003-0992", value:TRUE);
}
