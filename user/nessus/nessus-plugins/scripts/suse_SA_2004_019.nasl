#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:019
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13835);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SuSE-SA:2004:019: dhcp/dhcp-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:019 (dhcp/dhcp-server).


The Dynamic Host Configuration Protocol (DHCP) server is used to
configure clients that dynamically connect to a network (WLAN
hotspots, customer networks, ...).
The CERT informed us about a buffer overflow in the logging code of the
server that can be triggered by a malicious client by supplying multiple
hostnames. The hostname strings are concatenated and copied in a
fixed size buffer without checking the buffer bounds.
Other possible buffer overflow conditions exist in using vsprintf()
instead of vsnprintf(). This behavior can be configured during compile-
time. The dhcp/dhcp-server package coming with SUSE LINUX used the
vulnerable vsprintf() function.

Since SuSE Linux 8.1/SuSE Linux Enterprise Server 8 the DHCP server runs
as non-root user in a chroot jail. This setup limits the impact of a
successful attack.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_19_dhcp_server.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcp/dhcp-server package";
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
if ( rpm_check( reference:"dhcp-server-3.0.1rc6-22", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.1rc9-144", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.1rc10-61", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.1rc12-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.1rc13-28.15", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
