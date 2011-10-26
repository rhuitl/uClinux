#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:054
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19933);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:054: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:054 (evolution).


Several format string bugs allowed remote attackers to cause
evolution to crash or even execute code via full vCard data, contact
data from remote LDAP servers, task list data from remote servers
(CVE-2005-2549) or calendar entries (CVE-2005-2550).


Solution : http://www.suse.de/security/advisories/2005_54_evolution.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
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
if ( rpm_check( reference:"evolution-2.0.1-6.8", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.1-6.8", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.1-6.8", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-2.2.1-7.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-data-server-1.2.1-7.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-data-server-devel-1.2.1-7.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.2.1-7.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.2.1-7.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
