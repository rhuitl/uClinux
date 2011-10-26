#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12471);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");

 name["english"] = "RHSA-2004-073: metamail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated metamail packages that fix a number of vulnerabilities are now
  available.

  Metamail is a system for handling multimedia mail.

  Ulf Harnhammar discovered two format string bugs and two buffer overflow
  bugs in versions of Metamail up to and including 2.7. An attacker could
  create a carefully-crafted message such that when it is opened by a victim
  and parsed through Metamail, it runs arbitrary code as the victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CVE-2004-0104 (format strings) and CVE-2004-0105 (buffer
  overflows) to these issues.

  Users of Red Hat Enterprise Linux 2.1 are advised to upgrade to these
  erratum packages, which contain a backported security patch and are not
  vulnerable to these issues. Please note that Red Hat Enterprise Linux 3
  does not contain Metamail and is therefore not vulnerable to these issues.

  Red Hat would like to thank Ulf Harnhammar for the notification and patch
  for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-073.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the metamail packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"metamail-2.7-29", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"metamail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0104", value:TRUE);
 set_kb_item(name:"CVE-2004-0105", value:TRUE);
}

set_kb_item(name:"RHSA-2004-073", value:TRUE);
