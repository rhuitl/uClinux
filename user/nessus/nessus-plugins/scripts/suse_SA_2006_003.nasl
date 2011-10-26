#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:003
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20758);
 script_bugtraq_id(16325);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2006:003: kdelibs3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:003 (kdelibs3).


Maksim Orlovich discovered a bug in the JavaScript interpreter used
by Konqueror. UTF-8 encoded URLs could lead to a buffer overflow
that causes the browser to crash or execute arbitrary code.
Attackers could trick users into visiting specially crafted web
sites that exploit this bug (CVE-2006-0019).


Solution : http://www.suse.de/security/advisories/2006_03_kdelibs3.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs3 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs3-3.4.2-24.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.2-24.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.2.1-44.65", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.2.1-44.65", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.3.0-34.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.3.0-34.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.4.0-20.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.0-20.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
