#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:100
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18497);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0175");
 
 name["english"] = "MDKSA-2005:100: rsh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:100 (rsh).



A vulnerability in the rcp protocol was discovered that allows a server to
instruct a client to write arbitrary files outside of the current directory,
which could potentially be a security concern if a user used rcp to copy files
from a malicious server.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:100
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsh package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"rsh-0.17-13.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-server-0.17-13.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-0.17-13.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-server-0.17-13.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-0.17-13.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-server-0.17-13.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rsh-", release:"MDK10.0")
 || rpm_exists(rpm:"rsh-", release:"MDK10.1")
 || rpm_exists(rpm:"rsh-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
}
