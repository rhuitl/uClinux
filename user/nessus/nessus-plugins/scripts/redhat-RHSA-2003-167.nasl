#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12395);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0188");

 name["english"] = "RHSA-2003-167: lv";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated lv packages that fix the possibility of local privilege escalation
  are now available.

  Lv is a powerful file viewer similar to less. It can decode and encode
  multilingual streams through many coding systems, such as ISO-8859,
  ISO-2022, EUC, SJIS Big5, HZ, and Unicode.

  A bug has been found in versions of lv that read a .lv file in the current
  working directory. Any user who subsequently runs lv in that directory
  and uses the v (edit) command can be forced to execute an arbitrary
  program.

  Users are advised to upgrade to these erratum packages, which contain a
  version of lv that is patched to read the .lv configuration file only in
  the user\'s home directory.




Solution : http://rhn.redhat.com/errata/RHSA-2003-167.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lv packages";
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
if ( rpm_check( reference:"lv-4.49.4-3.21AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lv-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0188", value:TRUE);
}

set_kb_item(name:"RHSA-2003-167", value:TRUE);
