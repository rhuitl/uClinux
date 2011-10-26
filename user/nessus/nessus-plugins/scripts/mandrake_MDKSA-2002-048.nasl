#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13951);
 script_bugtraq_id(5084);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0653");
 
 name["english"] = "MDKSA-2002:048: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:048 (mod_ssl).


Frank Denis discovered an off-by-one error in mod_ssl dealing with the handling
of older configuration directorives (the rewrite_command hook). A malicious user
could use a specially-crafted .htaccess file to execute arbitrary commands as
the apache user or execute a DoS against the apache child processes.
This vulnerability is fixed in mod_ssl 2.8.10; patches have been applied to
correct this problem in these packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:048
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl package";
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
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.7-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK7.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK7.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0653", value:TRUE);
}
