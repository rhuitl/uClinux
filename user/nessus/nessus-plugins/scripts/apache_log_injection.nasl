#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
 
if (description) {
  script_id(12239);
  script_bugtraq_id(9930);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2003-0020");
  if (defined_func("script_xref")) {
    script_xref(name:"APPLE-SA", value:"APPLE-SA-2004-05-03");
    script_xref(name:"CLSA", value:"CLSA-2004:839");
    script_xref(name:"HPSB", value:"HPSBUX01022");
    script_xref(name:"RHSA", value:"RHSA-2003:139-07");
    script_xref(name:"RHSA", value:"RHSA-2003:243-07");
    script_xref(name:"MDKSA", value:"MDKSA-2003:050");
    script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
    script_xref(name:"SSA", value:"SSA:2004-133-01");
    script_xref(name:"SuSE-SA", value:"SuSE-SA:2004:009");
    script_xref(name:"TLSA", value:"TLSA-2004-11");
    script_xref(name:"TSLSA", value:"TSLSA-2004-0017");
  }
 
  name["english"] = "Apache Error Log Escape Sequence Injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running an Apache web server which allows for the
injection of arbitrary escape sequences into its error logs.  An
attacker might use this vulnerability in an attempt to exploit similar
vulnerabilities in terminal emulators. 

*****  Nessus has determined the vulnerability exists only by looking at
*****  the Server header returned by the web server running on the target.

Solution : Upgrade to Apache version 1.3.31 or 2.0.49 or newer.
Risk factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Apache Error Log Escape Sequence Injection Vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2006 George A. Theall");

  family["english"] = "Web Servers";
  script_family(english:family["english"]);
  if (!defined_func("bn_random") )
    script_dependencie("global_settings.nasl", "http_version.nasl");
  else
    script_dependencie("find_service.nes", "global_settings.nasl", "http_version.nasl", "redhat-RHSA-2003-244.nasl", "redhat_fixes.nasl", "macosx_SecUpd20040503.nasl", "macosx_SecUpd20040126.nasl", "macosx_SecUpd20041202.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if ( report_paranoia < 2 ) exit(0);

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for Apache Error Log Escape Sequence Injection vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (get_kb_item("CVE-2003-0020") || get_kb_item("RHSA-2003-244")) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port: port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);
if (debug_level) display("debug: server sig = >>", sig, "<<.\n");

# For affected versions of Apache, see:
#   - http://www.apacheweek.com/features/security-13
#   - http://www.apacheweek.com/features/security-20
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))|2\.0.([0-9][^0-9]|[0-3][0-9]|4[0-8]))", string:sig)) {
  security_warning(port);
}
