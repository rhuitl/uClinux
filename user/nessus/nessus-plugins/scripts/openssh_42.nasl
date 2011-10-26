#
# (C) Tenable Network Security
#


if (description) {
  script_id(19592);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2798");
  script_bugtraq_id(14729);

  name["english"] = "OpenSSH GSSAPI Credential Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote SSH server is susceptible to an information disclosure
vulnerability. 

Description :

According to its banner, the version of OpenSSH installed on the
remote host may allow GSSAPI credentials to be delegated to users who
log in using something other than GSSAPI authentication if
'GSSAPIDelegateCredentials' is enabled. 

See also : 

http://www.mindrot.org/pipermail/openssh-unix-announce/2005-September/000083.html

Solution : 

Upgrade to OpenSSH 4.2 or later.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for GSSAPI credential disclosure vulnerability in OpenSSH";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");


if (report_paranoia < 2) exit (0);


port = get_kb_item("Services/ssh");
if (!port) port = 22;


auth  =  get_kb_item("SSH/supportedauth/" + port);
if ( ! auth ) exit(0);
if ( "gssapi" >!< auth ) exit(0);

banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  banner = tolower(get_backport_banner(banner:banner));
  if (banner =~ "openssh[-_]([0-3]\.|4\.[01])")
    security_note(port);
}
