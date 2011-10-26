#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:070
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14053);
 script_bugtraq_id(7878, 7880, 7881, 7883);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0431", "CVE-2003-0432");
 
 name["english"] = "MDKSA-2003:070: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:070 (ethereal).


A number of string handling bugs were found in the packet dissectors in ethereal
that can be exploited using specially crafted packets to cause ethereal to
consume excessive amounts of memory, crash, or even execute arbitray code.
These vulnerabilities have been fixed upsteam in ethereal 0.9.13 and all users
are encouraged to upgrade.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:070
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.9.13-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0428", value:TRUE);
 set_kb_item(name:"CVE-2003-0429", value:TRUE);
 set_kb_item(name:"CVE-2003-0431", value:TRUE);
 set_kb_item(name:"CVE-2003-0432", value:TRUE);
}
