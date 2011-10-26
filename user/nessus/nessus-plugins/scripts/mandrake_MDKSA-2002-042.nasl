#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:042
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13946);
 script_bugtraq_id(4980);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0378");
 
 name["english"] = "MDKSA-2002:042: LPRng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:042 (LPRng).


Matthew Caron pointed out that using the LPRng default configuration, the lpd
daemon will accept job submissions from any remote host. These updated LPRng
packages modify the job submission policy in /etc/lpd.perms to refuse print jobs
from remote hosts by default.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:042
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the LPRng package";
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
if ( rpm_check( reference:"LPRng-3.7.4-7.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"LPRng-3.8.6-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"LPRng-", release:"MDK8.1")
 || rpm_exists(rpm:"LPRng-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0378", value:TRUE);
}
