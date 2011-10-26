#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0006
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13771);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:0006: dhcp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0006 (dhcp).


The ISC (Internet Software Consortium) dhcp package is an imple-
mentation of the 'Dynamic Host Configuration Protocol' (DHCP).
An internal source code audit done by ISC revealed several buffer
overflows in the code which is responsible to handle dynamic DNS
requests.
These bugs allow an attacker to gain remote access to the dhcp
server if the dynamic DNS feature is enabled.
Dynamic DNS is not enabled by default on SUSE LINUX.

As temporary fix you can disable dynamic DNS support and restart your
dhcp server. Otherwise install the new packages from our FTP servers.

Please backup your lease file before updating the package.
After the package update you have to restart the dhcp server
This can be done by executing the following commands as root:
- rcdhcpd restart
or (for older versions):
- rcdhcp restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_006_dhcp.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcp package";
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
if ( rpm_check( reference:"dhcpcd-1.3.19pl2-1", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0rc4-32", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcrelay-3.0rc12-56", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-base-3.0.1rc6-15", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.1rc9-59", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
