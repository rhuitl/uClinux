#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21233);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:020: clamav";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:020 (clamav).


Clamav was updated to version 0.88.1 to fix the following security
problems:

- An integer overflow in the PE header parser (CVE-2006-1614).

- Format string bugs in the logging code could potentially be
exploited to execute arbitrary code (CVE-2006-1615).

- Access to invalid memory could lead to a crash (CVE-2006-1630).


Solution : http://www.suse.de/security/advisories/2006_20_clamav.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the clamav package";
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
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
