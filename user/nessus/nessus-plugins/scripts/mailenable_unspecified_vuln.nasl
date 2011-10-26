#
# (C) Tenable Network Security
# Contains work by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15611);
  script_version("$Revision: 1.4 $");
  script_bugtraq_id(11578);
  name["english"] = "MailEnable Unspecified Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of MailEnable Professional which is
older than version 1.5.1.

The remote version of this software is known to be prone to an undisclosed
vulnerability which has been fixed in version 1.5.1.

Solution : Upgrade to MailEnable Professional 1.5.1
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the version of MailEnable";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "SMTP problems";
  script_family(english:family["english"]);

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
str = egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner);
if ( ! str ) exit(0);

ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:str, icase:TRUE);
if (ver == NULL || ver[1] == NULL ) exit(1);
ver = ver[2];
if (ver =~ "^1\.(2.*|5)([^.]|$)") security_hole(port);

