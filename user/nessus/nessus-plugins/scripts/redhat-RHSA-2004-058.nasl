#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12464);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0973", "CVE-2004-0096");

 name["english"] = "RHSA-2004-058: mod_python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mod_python packages that fix a denial of service vulnerability are
  now available for Red Hat Enterprise Linux.

  mod_python embeds the Python language interpreter within the Apache httpd
  server.

  A bug has been found in mod_python versions 2.7.10 and earlier that can
  lead to a denial of service vulnerability. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2003-0973 to
  this issue.

  Although Red Hat Enterprise Linux shipped with a version of mod_python that
  contains this bug, our testing was unable to trigger the denial of service
  vulnerability. However, mod_python users are advised to upgrade to these
  errata packages, which contain a backported patch that corrects this bug.




Solution : http://rhn.redhat.com/errata/RHSA-2004-058.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_python packages";
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
if ( rpm_check( reference:"mod_python-2.7.8-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_python-3.0.3-3.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_python-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0973", value:TRUE);
 set_kb_item(name:"CVE-2004-0096", value:TRUE);
}
if ( rpm_exists(rpm:"mod_python-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0973", value:TRUE);
 set_kb_item(name:"CVE-2004-0096", value:TRUE);
}

set_kb_item(name:"RHSA-2004-058", value:TRUE);
