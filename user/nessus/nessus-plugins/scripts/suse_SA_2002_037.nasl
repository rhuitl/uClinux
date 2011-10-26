#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13758);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:037: heartbeat";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:037 (heartbeat).


Heartbeat is a monitoring service that is used to implement
failover in high-availablity environments. It can be configured to
monitor other systems via serial connections, or via UDP/IP.

Several format string bugs have been discovered in the heartbeat
package.  One of these format string bugs is in the normal path
of execution, all the remaining ones can only be triggered if
heartbeat is running in debug mode. Since heartbeat is running with
root privilege, this problem can possibly be exploited by remote
attackers, provided they are able to send packets to the UDP port
heartbeat is listening on (port 694 by default).

Vulnerable versions of heartbeat are included in SUSE LINUX 8.0 and
SUSE LINUX 8.1.

As a workaround, make sure that your firewall blocks all traffic
to the heartbeat UDP port.

The proper fix is to upgrade to the packages provided by SUSE.
In addition to fixing the format string bug, this update also
changes heartbeat to perform processing of network packets as
user 'nobody' instead of root. The update package for SUSE LINUX
8.1 also fixes a boot time problem with heartbeat.

SUSE wishes to thank Nathan Wallwork for reporting the bug, and Alan
Robertson for his assistance in dealing with this problem. For more
information on this vulnerability, please refer to
http://linux-ha.org/security/sec01.html

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.


Solution : http://www.suse.de/security/2002_037_heartbeat.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the heartbeat package";
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
if ( rpm_check( reference:"heimdal-lib-0.4d-132", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heartbeat-0.4.9.1-159", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heartbeat-ldirectd-0.4.9.1-159", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heartbeat-stonith-0.4.9.1-159", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
