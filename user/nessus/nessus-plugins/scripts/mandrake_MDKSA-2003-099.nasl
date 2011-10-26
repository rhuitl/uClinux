#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:099
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14081);
 script_bugtraq_id(8594, 8595, 8596, 8597, 8600);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
 
 name["english"] = "MDKSA-2003:099: sane";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:099 (sane).


Several vulnerabilities were discovered in the saned daemon, a part of the sane
package, which allows for a scanner to be used remotely. The IP address of the
remote host is only checked after the first communication occurs, which causes
the saned.conf restrictions to be ignored for the first connection. As well, a
connection that is dropped early can cause Denial of Service issues due to a
number of differing factors. Finally, a lack of error checking can cause various
other unfavourable actions.
The provided packages have been patched to correct the issues. sane, as
distributed in Mandrake Linux 9.1 and higher, have versions where the fixes were
applied upstream.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:099
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sane package";
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
if ( rpm_check( reference:"libsane1-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsane1-devel-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sane-backends-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sane-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0773", value:TRUE);
 set_kb_item(name:"CVE-2003-0774", value:TRUE);
 set_kb_item(name:"CVE-2003-0775", value:TRUE);
 set_kb_item(name:"CVE-2003-0776", value:TRUE);
 set_kb_item(name:"CVE-2003-0777", value:TRUE);
 set_kb_item(name:"CVE-2003-0778", value:TRUE);
}
