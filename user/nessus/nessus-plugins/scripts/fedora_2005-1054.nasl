#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20166);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-2672", "CVE-2005-2672");
 
 name["english"] = "Fedora Core 3 2005-1054: lm_sensors";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1054 (lm_sensors).

The lm_sensors package includes a collection of modules for general SMBus
access and hardware monitoring.  NOTE: this requires special support which
is not in standard 2.2-vintage kernels.

Update Information:

The lm_sensors package includes a collection of modules for
general SMBus access and hardware monitoring. NOTE: this
package requires special support which is not in standard
2.2-vintage kernels.

A bug was found in the pwmconfig tool which uses temporary
files in an insecure manner. The pwconfig tool writes a
configuration file which may be world readable for a short
period of time. This file contains various information about
the setup of lm_sensors on that machine. It could be
modified within the short window to contain configuration
data that would either render lm_sensors unusable or in the
worst case even hang the machine resulting in a DoS. The
Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2672 to this issue.

Users of lm_sensors are advised to upgrade to these updated
packages, which contain a patch which resolves this issue.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lm_sensors package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lm_sensors-2.8.7-2.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-devel-2.8.7-2.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lm_sensors-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-2672", value:TRUE);
 set_kb_item(name:"CVE-2005-2672", value:TRUE);
}
