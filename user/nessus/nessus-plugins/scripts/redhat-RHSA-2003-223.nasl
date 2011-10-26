#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12406);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1563");

 name["english"] = "RHSA-2003-223: stunnel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated stunnel packages are now available. These updates correct a
  potential vulnerability in stunnel\'s signal handling.

  Stunnel is a wrapper for network connections. It can be used to tunnel an
  unencrypted network connection over a secure connection (encrypted using
  SSL or TLS) or to provide a secure means of connecting to services that do
  not natively support encryption.

  When configured to listen for incoming connections (instead of being
  invoked by xinetd), stunnel can be configured to either start a thread or a
  child process to handle each new connection. If Stunnel is configured to
  start a new child process to handle each connection, it will receive a
  SIGCHLD signal when that child exits.

  Stunnel versions prior to 4.04 would perform tasks in the SIGCHLD signal
  handler which, if interrupted by another SIGCHLD signal, could be unsafe.
  This could lead to a denial of service.

  All users are urged to upgrade to these errata packages, which modify
  stunnel\'s signal handler so that it is not vulnerable to this issue.

  NOTE: After upgrading, any instances of stunnel configured to run in daemon
  mode should be restarted, and any active network connections that are
  currently being serviced by stunnel should be terminated and reestablished.




Solution : http://rhn.redhat.com/errata/RHSA-2003-223.html
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
if ( rpm_check( reference:"stunnel-3.22-5.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"stunnel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1563", value:TRUE);
}

set_kb_item(name:"RHSA-2003-223", value:TRUE);
