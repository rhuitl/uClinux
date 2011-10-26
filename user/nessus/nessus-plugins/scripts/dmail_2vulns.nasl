#
# (C) Tenable Network Security
#


if (description) {
  script_id(18200);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1478", "CVE-2005-1516");
  script_bugtraq_id(13497, 13505);

  name["english"] = "NetWin DMail Two Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server is susceptible to multiple types of attacks. 

Description :

The version of NetWin DMail on the remote host suffers from an
authentication bypass vulnerability in its mailing list server
component, DList, and a format string vulnerability in the SMTP server
component, DSmtp.  An attacker can exploit the first to reveal
potentially sensitive log information as well as to shut down the
DList process and, provided he has the admin password, the second to
crash the DSmtp process and potentially execute arbitrary code on the
remote. 

See also : 

http://www.security.org.sg/vuln/dmail31a.html

Solution : 

Block access to the affected port with a firewall.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:H/Au:R/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for two vulnerabilities in NetWin DMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/DMAIL_Admin", 7111);

  exit(0);
}


include("misc_func.inc");


port = get_kb_item("Services/DMAIL_Admin");
if (!port) port = 7111;
if (!get_port_state(port)) exit(0);


# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) exit(0);
res = recv_line(socket:soc, length:4096);


# If it looks like DMail's DMAdmin...
if (res && res =~ "^hash [0-9]+") {
  # Try to exploit the vulnerability by grabbing the logs.
  send(socket:soc, data:string("sendlog 234343\n"));
  res = recv_line(socket:soc, length:4096);

  # There's a problem if Dlist claims to be sending them.
  if (res && res =~ "^ok Dlist .+ sending log") security_warning(port);
}
close(soc);
