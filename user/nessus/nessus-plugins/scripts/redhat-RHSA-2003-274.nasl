#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12420);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0720", "CVE-2003-0721");

 name["english"] = "RHSA-2003-274: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Pine packages that resolve remotely exploitable security issues are
  now available.

  Pine, developed at the University of Washington, is a tool for reading,
  sending, and managing electronic messages (including mail and news).

  A buffer overflow exists in the way unpatched versions of Pine prior to
  4.57 handle the \'message/external-body\' type. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0720
  to this issue.

  An integer overflow exists in the Pine MIME header parsing in versions
  prior to 4.57. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0721 to this issue.

  Both of these flaws could be exploited by a remote attacker sending a
  carefully crafted email to the victim that will execute arbitrary code when
  the email is opened using Pine.

  All users of Pine are advised to upgrade to these erratum packages, which
  contain a backported security patch correcting these issues.

  Red Hat would like to thank iDefense for bringing these issues to our
  attention and the University of Washington for the patch.




Solution : http://rhn.redhat.com/errata/RHSA-2003-274.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine packages";
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
if ( rpm_check( reference:"pine-4.44-19.21AS.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pine-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0720", value:TRUE);
 set_kb_item(name:"CVE-2003-0721", value:TRUE);
}

set_kb_item(name:"RHSA-2003-274", value:TRUE);
