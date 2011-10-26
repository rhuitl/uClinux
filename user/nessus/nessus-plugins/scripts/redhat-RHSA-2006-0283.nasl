#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21363);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");

 name["english"] = "RHSA-2006-0283:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squirrelmail package that fixes three security and many other
  bug issues is now available. This update contains bug fixes of upstream
  squirrelmail 1.4.6 with some additional improvements to international
  language support.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  A bug was found in the way SquirrelMail presents the right frame to the
  user. If a user can be tricked into opening a carefully crafted URL, it is
  possible to present the user with arbitrary HTML data. (CVE-2006-0188)

  A bug was found in the way SquirrelMail filters incoming HTML email. It is
  possible to cause a victim\'s web browser to request remote content by
  opening a HTML email while running a web browser that processes certain
  types of invalid style sheets. Only Internet Explorer is known to process
  such malformed style sheets. (CVE-2006-0195)

  A bug was found in the way SquirrelMail processes a request to select an
  IMAP mailbox. If a user can be tricked into opening a carefully crafted
  URL, it is possible to execute arbitrary IMAP commands as the user viewing
  their mail with SquirrelMail. (CVE-2006-0377)

  Users of SquirrelMail are advised to upgrade to this updated package, which
  contains SquirrelMail version 1.4.6 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0283.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   squirrelmail packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"  squirrelmail-1.4.6-5.el3.noarch.rpm      248e27d4444f0325d0147d4182d578b6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-0188", value:TRUE);
 set_kb_item(name:"CVE-2006-0195", value:TRUE);
 set_kb_item(name:"CVE-2006-0377", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0283", value:TRUE);
