#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12393);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0211");

 name["english"] = "RHSA-2003-161: xinetd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated xinetd packages fix a security vulnerability and other bugs.

  Xinetd is a master server that is used to to accept service
  connection requests and start the appropriate servers.

  Because of a programming error, memory was allocated and never freed if a
  connection was refused for any reason. An attacker could exploit this flaw
  to crash the xinetd server, rendering all services it controls unavaliable.

  In addition, other flaws in xinetd could cause incorrect operation in
  certain unusual server configurations.

  All users of xinetd are advised to update to the packages listed in this
  erratum, which contain an upgrade to xinetd-2.3.11 and are not vulnerable
  to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-161.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xinetd packages";
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
if ( rpm_check( reference:"xinetd-2.3.11-2.AS2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xinetd-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0211", value:TRUE);
}

set_kb_item(name:"RHSA-2003-161", value:TRUE);
