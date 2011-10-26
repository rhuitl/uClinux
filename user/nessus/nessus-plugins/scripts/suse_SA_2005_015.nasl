#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17325);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:015: openslp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:015 (openslp).


The SUSE Security Team reviewed critical parts of the OpenSLP package,
an open source implementation of the Service Location Protocol (SLP).
SLP is used by Desktops to locate certain services such as printers and
by servers to announce their services.
During the audit, various buffer overflows and out of bounds memory access
have been fixed which can be triggered by remote attackers by sending
malformed SLP packets.


Solution : http://www.suse.de/security/advisories/2005_15_openslp.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openslp package";
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
if ( rpm_check( reference:"openslp-1.1.5-73.15", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openslp-server-1.1.5-73.15", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openslp-devel-1.1.5-73.15", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openslp-1.1.5-80.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openslp-server-1.1.5-80.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openslp-devel-1.1.5-80.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
