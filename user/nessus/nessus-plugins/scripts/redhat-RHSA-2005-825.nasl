#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20205);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2672");

 name["english"] = "RHSA-2005-825: lm_sensors";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated lm_sensors packages that fix an insecure file issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The lm_sensors package includes a collection of modules for general SMBus
  access and hardware monitoring. This package requires special support which
  is not in standard version 2.2 kernels.

  A bug was found in the way the pwmconfig tool creates temporary files. It
  is possible that a local attacker could leverage this flaw to overwrite
  arbitrary files located on the system. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2005-2672 to this issue.

  Users of lm_sensors are advised to upgrade to these updated packages, which
  contain a backported patch that resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-825.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lm_sensors packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lm_sensors-2.8.7-2.40.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-devel-2.8.7-2.40.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lm_sensors-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2672", value:TRUE);
}

set_kb_item(name:"RHSA-2005-825", value:TRUE);
