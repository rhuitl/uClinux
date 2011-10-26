#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21677);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2830");
  script_bugtraq_id(18301);

  script_name(english:"Rendezvous HTTP Interface Buffer Overflow  Vulnerability");
  script_summary(english:"Checks version number in Rendezvous' HTTP banner");

  desc = "
Synopsis :

The remote server is prone to a buffer overflow attack. 

Description :

The remote host appears to be running Rendezvous, a commercial
messaging software product used for building distributed applications

According to its banner, several of the components in the version of
Rendezvous installed on the remote host contain a buffer overflow
vulnerability in the HTTP administrative interface that may allow
arbitrary code execution subject to the privileges of the user that
invoked the daemon, or 'nobody' in the case the remote system is
'unix' and the invoking user was 'root'. 

See also :

http://www.tibco.com/resources/mk/rendezvous_security_advisory.txt
http://www.kb.cert.org/vuls/id/999884

Solution :

Upgrade to Rendezvous 7.5.1 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7580, 7585);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:7580);
if (!get_port_state(port)) exit(0);


# There's a problem if the banner is for Rendezvous < 7.5.1.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: .+Rendezvous HTTP Server ([0-6]\.|7\.([0-4]\.|5\.0))", string:banner)
) security_note(port);
