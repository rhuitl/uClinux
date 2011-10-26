#
# (C) Tenable Network Security
#


if (description) {
  script_id(19238);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1101");
  script_bugtraq_id(13130);

  name["english"] = "Lotus Domino Server Date Fields Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is susceptible to a buffer overflow
vulnerability. 

Description :

According to its banner, the remote host is running a version of Lotus
Domino Server that is prone to a buffer overflow that can be triggered
by submitting a POST request with large amounts of data for certain
date / time fields.  A remote attacker can reportedly exploit this
flaw to crash the web server or to execute arbitrary code on the
affected host. 

See also : 

http://www.ngssoftware.com/advisories/lotus-01.txt
http://www-1.ibm.com/support/docview.wss?rs=899&uid=swg21202431

Solution : 

Upgrade to Lotus Domino Server version 6.0.5 / 6.5.4 Maintenance
Release or later. 

Risk factor : 

Medium / CVSS Base Score : 4
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for date fields overflow vulnerability in Lotus Domino Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "Lotus Domino" >!< banner) exit(0);


# Check the version number.
#
# nb: Litchfield claims 6.0.5 and 6.5.4 are affected, and earlier versions
#     may also be. Also note that there are no versions 6.1.x - 6.4.x per 
#     the Fix List at 
#     <http://www-10.lotus.com/ldd/r5fixlist.nsf/Public?OpenView>.
if (egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.(0\.[0-5]|5\.[0-4]))"))
  security_warning(port);
