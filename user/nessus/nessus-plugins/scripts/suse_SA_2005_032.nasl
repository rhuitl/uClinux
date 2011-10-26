#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19241);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0024");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SUSE-SA:2005:032: java2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:032 (java2).


Two security bugs in the SUN Java implementation have been fixed.

Java Web Start can be exploited remotely due to an error in input
validation of tags in JNLP files, so an attacker can pass arbitrary
command-line options to the virtual machine to disable the sandbox
and get access to files.

This is tracked by the Mitre CVE ID CVE-2005-0836.

The second bug is equal to the first one but can also triggered by
untrusted applets.

This is tracked by the Mitre CVE ID CVE-2005-1974.


Solution : http://www.suse.de/security/advisories/2005_32_java2.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the java2 package";
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
if ( rpm_check( reference:"java2-1.4.2-144", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-144", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-1.4.2-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-1.4.2-129.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-129.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
