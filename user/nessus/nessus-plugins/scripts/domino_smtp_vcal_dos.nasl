#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21778);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0119");
  script_bugtraq_id(18020);

  script_name(english:"Lotus Domino SMTP Server Malformed vcal Denial of Service Vulnerability");
  script_summary(english:"Checks version of Lotus Domino SMTP server");

  desc = "
Synopsis :

The remote SMTP server is susceptible to a denial of service attack. 

Description :

The remote host is running Lotus Domino, a messaging and collaboration
application suite. 

According to the version number in its banner, the SMTP server bundled
with Lotus Domino on the remote host reportedly suffers from a denial
of service flaw.  Specifically, the routing server will consumes 100%
of the CPU when attempting to process a malformed 'vcal' meeting
request.  An unauthenticated attacker may be able to leverage this
issue to deny service to legitimate users. 

See also : 

http://www.securityfocus.com/advisories/10761
http://www.nessus.org/u?3532045c

Solution : 

Upgrade to Lotus Domino 6.5.4 FP1, 6.5.5 or 7.0 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Check the banner.
banner = get_smtp_banner(port:port);
if (
  banner &&
  "Lotus Domino Release" >< banner &&
  egrep(pattern:"Release ([0-5]\.|6\.([0-4]|5\.([0-3]|4\))))", string:banner)
) security_warning(port);
