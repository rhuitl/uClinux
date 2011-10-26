#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14712);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(11144);
# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 10/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"9789");
    script_xref(name:"OSVDB", value:"10727");
  }

  name["english"] = "MailEnable SMTP Connector Service DNS Lookup DoS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailEnable's SMTP
Connector service.  A flaw exists in both the Standard Edition 1.7x
and Professional Edition 1.2x/1.5a-e that results in this service
crashing if it receives a DNS response with over 100 MX records.  A
remote attacker can exploit this to perform a DoS attack against the
SMTP server on the target. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of MailEnable
***** installed there.

Solution : Upgrade to MailEnable Standard Edition 1.8 / Professional
Edition 1.5e or greater. 

Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for DNS Lookup DoS Vulnerability in MailEnable SMTP Connector Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "smtpserver_detect.nasl");
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

if (debug_level) display("debug: searching for DNS Lookup DoS vulnerability in MailEnable SMTP Connector service on ", host, ":", port, ".\n");

# We have to rely only on the banner, which unfortunately is not 
# updated by the hotfix.
banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);
if (debug_level) display("debug: banner =>>", banner, "<<.\n");
if (banner !~ "Mail(Enable| Enable SMTP) Service") exit(0);

# nb: Standard Edition seems to format version as "1.71--" (for 1.71)
#     while Professional Edition formats it like "0-1.2-" (for 1.2).
ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:banner, icase:TRUE);
if (ver == NULL) {
  if (log_verbosity > 1) display("Can't determine version number of MailEnable's SMTP Connector service!\n");
  exit(1);
}
if (ver[1] == NULL) {
  edition = "Standard";
}
else if (ver[1] == "0-") {
  edition = "Professional";
}
if (isnull(edition)) {
  if (log_verbosity > 1) display("Can't determine edition of MailEnable's SMTP Connector service!\n");
  exit(1);
}
ver = ver[2];
if (debug_level) display("debug: MailEnable ", edition, " Edition SMTP Connector, version =>>", ver, "<<\n");
if (edition == "Standard") {
  # nb: see <http://www.mailenable.com/standardhistory.html> for history.
  if (ver =~ "^1\.7") security_warning(port);
}
else if (edition == "Professional") {
  # nb: there were no version 1.3x or 1.4x; see 
  #     <http://www.mailenable.com/professionalhistory.html>.
  if (ver =~ "^1\.(2|5[a-e])") security_warning(port);
}
