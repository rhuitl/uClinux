#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:011
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21013);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:011: heimdal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:011 (heimdal).


Heimdal is a Kerberos 5 implementation from the Royal Institut of Techno-
logy in Stockholm.
This update fixes two bugs in heimdal. The first one occurs in the rsh
daemon and allows an authenticated malicious user to gain ownership of
files that belong to other users (CVE-2006-0582).
The second bug affects the telnet server and can be used to crash the server
before authentication happens. It is even a denial-of-service attack when
the telnetd is started via inetd because inetd stops forking the daemon
when it forks too fast (CVE-2006-0677).


Solution : http://www.suse.de/security/advisories/2006_11_heimdal.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the heimdal package";
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
if ( rpm_check( reference:"heimdal-0.6.1rc3-55.21", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-devel-0.6.1rc3-55.21", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-lib-0.6.1rc3-55.21", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.6.2-8.6", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-devel-0.6.2-8.6", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-lib-0.6.2-8.6", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-tools-0.6.2-8.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-tools-devel-0.6.2-8.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
