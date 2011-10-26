#
# (C) Tenable Network Security
#
#
# A big thanks to Andrew Daviel
#

if(description)
{
 script_id(14819);
 script_cve_id("CVE-2004-2166");
 script_bugtraq_id(11247);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Canon ImageRUNNER Printer Email Printing";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be a Canon ImageRUNNER printer, running an SMTP 
service.

It is possible to send an email to the remote service and it will print 
its content. An attacker may use this flaw to send an endless stream of
emails to the remote device and cause a denial of service by using all
the paper of the remote printer.

Solution : Disable the email printing service using the web interface.
Risk factor : Low";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Determines if the remote host is a Canon ImageRUNNER Printer";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if(!port)port = 25;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = smtp_recv_line(socket:soc);
if ( ! banner ) exit(0);

if ( !ereg(pattern:"^220 .* SMTP Ready.$", string:banner ) ) exit(0);
send(socket:soc, data:'EHLO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^550 Command unrecognized", string:banner) ) exit(0);
send(socket:soc, data:'HELO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 . Hello there \[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\] please to meet you\.", string:banner) ) exit(0);

send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^503 need MAIL From: first\.", string:r) ) exit(0);

send(socket:soc, data:'MAIL FROM: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Sender Ok", string:r) ) exit(0);
send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Receiver Ok", string:r) ) exit(0);

security_note(port);
