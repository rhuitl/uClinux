#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12426);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0740");

 name["english"] = "RHSA-2003-297: stunnel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated stunnel packages are now available. These updates address problems
  stemming from improper use of non-reentrant functions in signal handlers.

  Stunnel is a wrapper for network connections. It can be used to tunnel an
  unencrypted network connection over an encrypted connection (encrypted
  using SSL or TLS) or to provide an encrypted means of connecting to
  services that do not natively support encryption.

  A previous advisory provided updated packages to address re-entrancy
  problems in stunnel\'s signal-handling routines. These updates did not
  address other bugs that were found by Steve Grubb, and introduced an
  additional bug, which was fixed in stunnel 3.26.

  All users should upgrade to these errata packages, which address these
  issues by updating stunnel to version 3.26.

  NOTE: After upgrading, any instances of stunnel configured to run in daemon
  mode should be restarted, and any active network connections that are
  currently being serviced by stunnel should be terminated and reestablished.




Solution : http://rhn.redhat.com/errata/RHSA-2003-297.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the stunnel packages";
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
if ( rpm_check( reference:"stunnel-3.26-1.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"stunnel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0740", value:TRUE);
}

set_kb_item(name:"RHSA-2003-297", value:TRUE);
