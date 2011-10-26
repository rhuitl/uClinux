#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:184
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20043);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2960", "CVE-2005-3137");
 
 name["english"] = "MDKSA-2005:184: cfengine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:184 (cfengine).



Javier Fernández-Sanguino Peña discovered several insecure temporary file uses
in cfengine <= 1.6.5 and <= 2.1.16 which allows local users to overwrite
arbitrary files via a symlink attack on temporary files used by vicf.in.
(CVE-2005-2960)

In addition, Javier discovered the cfmailfilter and cfcron.in files for
cfengine <= 1.6.5 allow local users to overwrite arbitrary files via a symlink
attack on temporary files (CVE-2005-3137)

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:184
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cfengine package";
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
if ( rpm_check( reference:"cfengine-1.6.5-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-2.1.12-7.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfservd-2.1.12-7.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-base-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfagent-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfenvd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfexecd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfservd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cfengine-", release:"MDK10.1")
 || rpm_exists(rpm:"cfengine-", release:"MDK10.2")
 || rpm_exists(rpm:"cfengine-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2960", value:TRUE);
 set_kb_item(name:"CVE-2005-3137", value:TRUE);
}
