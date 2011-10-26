#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19672);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2491");

 name["english"] = "RHSA-2005-358: exim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated exim packages that fix a security issue in PCRE and a free space
  computation on large file system bug are now available for Red Hat
  Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on Unix systems connected to the Internet.

  An integer overflow flaw was found in PCRE, a Perl-compatible regular
  expression library included within Exim. A local user could create a
  maliciously crafted regular expression in such as way that they could gain
  the privileges of the \'exim\' user. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-2491 to this issue. These
  erratum packages change Exim to use the system PCRE library instead of the
  internal one.

  These packages also fix a minor flaw where the Exim Monitor was incorrectly
  computing free space on very large file systems.

  Users should upgrade to these erratum packages and also ensure they have
  updated the system PCRE library, for which erratum packages are available
  seperately in RHSA-2005:761




Solution : http://rhn.redhat.com/errata/RHSA-2005-358.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the exim packages";
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
if ( rpm_check( reference:"exim-4.43-1.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"exim-doc-4.43-1.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"exim-mon-4.43-1.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"exim-sa-4.43-1.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"exim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}

set_kb_item(name:"RHSA-2005-358", value:TRUE);
