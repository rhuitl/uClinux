#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12360);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1335", "CVE-2002-1348");

 name["english"] = "RHSA-2003-045: w";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated W3M packages are available that fix two cross-site scripting
  issues.

  W3M is a pager with Web browsing capabilities. Two cross-site scripting
  (XSS) issues have been found in W3M.

  An XSS vulnerability in W3M 0.3.2 allows remote attackers to insert
  arbitrary HTML and Web script into frames. Frames are disabled by default
  in the version of W3M shipped with Red Hat Linux Advanced Server and Red
  Hat Linux Advanced Workstation. Therefore, this problem will not appear as
  long as users do not use W3M with the -F option, or enable frame support in
  either the /etc/w3m/w3mconfig or ~/.w3m/config configuration files. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2002-1335 to this issue.

  An XSS vulnerability in versions of W3M before 0.3.2.2 allows attackers to
  insert arbitrary HTML and Web script into image attributes. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2002-1348 to this issue.

  Users of W3M are advised to upgrade to the updated packages containing W3M
  0.2.1 and a patch to correct these vulnerabilities.




Solution : http://rhn.redhat.com/errata/RHSA-2003-045.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the w packages";
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
if ( rpm_check( reference:"w3m-0.2.1-11.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"w-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1335", value:TRUE);
 set_kb_item(name:"CVE-2002-1348", value:TRUE);
}

set_kb_item(name:"RHSA-2003-045", value:TRUE);
