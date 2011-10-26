#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:030
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14667);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0032");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0748", "CVE-2004-0751");
 script_bugtraq_id(11154);
 
 name["english"] = "SUSE-SA:2004:030: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:030 (apache2).


The mod_ssl apache module, as part of our apache2 package, enables
the apache webserver to handle the HTTPS protocol.
Within the mod_ssl module, two Denial of Service conditions in the
input filter have been found. The CVE project assigned the identifiers
CVE-2004-0748 and CVE-2004-0751 to these issues.


Solution : http://www.suse.de/security/2004_30_apache2.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"apache2-2.0.48-135", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-135", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-135", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.48-135", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-135", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-135", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-135", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.48-135", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-135", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-135", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-135", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.49-27.11", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.49-27.11", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.49-27.11", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.49-27.11", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"SUSE8.1")
 || rpm_exists(rpm:"apache2-", release:"SUSE8.2")
 || rpm_exists(rpm:"apache2-", release:"SUSE9.0")
 || rpm_exists(rpm:"apache2-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0748", value:TRUE);
 set_kb_item(name:"CVE-2004-0751", value:TRUE);
}
