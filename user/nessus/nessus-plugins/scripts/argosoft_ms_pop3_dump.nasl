#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote POP3 server is subject to an information disclosure issue. 

Description :

The remote host is running ArGoSoft Mail Server, a messaging system
for Windows. 

An unauthenticated attacker can gain information about the installed
application as well as the remote host itself by sending the '_DUMP'
command to the POP3 server. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2006-02/0438.html
http://www.argosoft.com/rootpages/mailserver/ChangeList.aspx

Solution :

Upgrade to ArGoSoft Mail Server 1.8.8.6 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20976);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0928");
  script_bugtraq_id(16808);

  script_name(english:"ArGoSoft Mail Server _DUMP Command Information Disclosure Vulnerability");
  script_summary(english:"Checks for _DUMP command information disclosure vulnerability in ArGoSoft POP3 server");

  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");

  exit(0);
}


include("global_settings.inc");
include("pop3_func.inc");


if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure the banner is from ArGoSoft.
banner = get_pop3_banner(port:port);
if (!banner || "+OK ArGoSoft Mail Server" >!< banner) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);


# Try to exploit the flaw.
c = string("_DUMP");
send(socket:soc, data:string(c, "\r\n"));
n = 0;
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s);
  if (!isnull(m)) {
    resp = m[1];
    if ("-ERR" >< resp) break;
  }
  else if (s == ".") break;
  else info += s + '\n';
  n ++;
  if ( n > 200 ) break;
}


# There's a problem if we got a response.
if (info) {
  if (report_verbosity > 1) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      info
    );
  }
  else report = desc;

  security_note(port:port, data:report);
}


# Clean up.
close(soc);
