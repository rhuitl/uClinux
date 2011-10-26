#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote NTP server is affected by a privilege escalation issue. 

Description :

According to its version number, the NTP (Network Time Protocol)
server installed on the remote host suffers from a flaw that may cause
it to run with the permissions of a privileged user if a group name
rather than a group id is specified on the commandline.  As a result,
an attacker that manages to compromise the application through some
other means will gain elevated privileges than what is expected. 

See also : 

https://ntp.isc.org/bugs/show_bug.cgi?id=392

Solution :

Start ntpd with a group number or upgrade to NTP 4.2.1 or later.  

Risk factor : 

Low / CVSS Base Score : 2 
(AV:L/AC:L/Au:NR/C:N/A:N/I:P/B:N)";


if (description) {
  script_id(19517);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2496");
  script_bugtraq_id(14673);

  name["english"] = "ntpd Incorrect Group Privileges Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for incorrect group privileges vulnerability in ntpd";

  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("ntp_open.nasl");
  script_require_keys("NTP/Running");

  exit(0);
}


include('global_settings.inc');


if (report_paranoia < 2) exit(0);


port = 123;
soc = open_sock_udp(port);
if (!get_udp_port_state(port)) exit(0);


# Pull up the version number.
#
# nb: this replicates "echo rv | ntpq target".
pkt = raw_string(
  0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);
send(socket:soc, data:pkt);
res = recv(socket:soc, length:4096);
close(soc);

if (res) {
  ver = strstr(res, 'version="ntpd ');
  if (ver) ver = ver - 'version="ntpd ';
  if (ver) ver = ver - strstr(ver, " ");

  # The bug report says the flaw is fixed in 4.2.1.
  if (ver && ver =~ "^([0-3]\.|4\.([01]|2\.0))")
    security_note(port:port, protocol:"udp", data:desc["english"]);
}

