#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16264);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0086");

 name["english"] = "RHSA-2005-068: less";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated less package that fixes segmentation fault when viewing binary
  files is now available.

  The less utility is a text file browser that resembles more, but has
  extended capabilities.

  Victor Ashik discovered a heap based buffer overflow in less, caused by a
  patch added to the less package in Red Hat Enterprise Linux 3. An attacker
  could construct a carefully crafted file that could cause less to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-0086
  to this issue. Note that this issue only affects the version of less
  distributed with Red Hat Enterprise Linux 3.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to remotely exploit this vulnerability on x86
  architectures.

  All users of the less package should upgrade to this updated package,
  which resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-068.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the less packages";
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
if ( rpm_check( reference:"less-378-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"less-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0086", value:TRUE);
}

set_kb_item(name:"RHSA-2005-068", value:TRUE);
