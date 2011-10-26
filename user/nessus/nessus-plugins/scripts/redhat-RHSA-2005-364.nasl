#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18094);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1061");

 name["english"] = "RHSA-2005-364:   logwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated logwatch package that fixes a denial of service issue is now
  available.

  This update has been rated as having moderate security impact by the
  Red Hat Security Response Team.

  LogWatch is a customizable log analysis system. LogWatch parses
  through your system\'s logs for a given period of time and creates a
  report analyzing areas that you specify, in as much detail as you
  require.

  A bug was found in the logwatch secure script. If an attacker is able to
  inject an arbitrary string into the /var/log/secure file, it is possible to
  prevent logwatch from detecting malicious activity. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1061 to this issue.

  All users of logwatch are advised to upgrade to this updated
  package, which contain backported fixes for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-364.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   logwatch packages";
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
if ( rpm_check( reference:"  logwatch-2.6-2.EL2.noarch.rpm            b112e89085531f4b37ea8c2b2b40ad6e", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  logwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1061", value:TRUE);
}

set_kb_item(name:"RHSA-2005-364", value:TRUE);
