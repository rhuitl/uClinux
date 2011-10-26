#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18036);
  script_version("$Revision: 1.6 $");
  script_cve_id("CVE-2005-1077", "CVE-2005-1078", "CVE-2005-2043");
  script_bugtraq_id(13131, 13128, 13127, 13126, 13982, 13983);
  name["english"] = "Multiple Vulnerabilities in XAMPP";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains several applications that may use default
passwords and be prone to cross-site scripting and directory traversal
attacks. 

Description :

The remote host is running XAMP, an Apache distribution containing
MySQL, PHP, and Perl.  It is designed for easy installation and
administration. 

The remote version of this software contains various security flaws
and password disclosure weaknesses which may allow an attacker to
perform cross-site scripting attacks against the remote host or to
gain administrative access on the remote host if no password has been
set. 

See also :

http://marc.theaimsgroup.com/?l=full-disclosure&m=111330048629182&w=2
http://sourceforge.net/project/shownotes.php?release_id=335710

Solution : 

Upgrade to XAMPP 1.4.14 or newer.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the version of XAMPP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

req = http_get(item:"/xampp/start.php", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( ! res ) exit(0);

if ( egrep(pattern:"(Bienvenido a|Willkommen zu|Welcome to) XAMPP .* 1\.([0-3]\.|4\.[0-9][^0-9]|4\.1[0-3][^0-9])", string:res) ) security_warning(port);
