#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL...
#
# Credits: Berend-Jan Wever
#

if(description)
{
 script_id(11270);
 script_version ("$Revision: 1.2 $");
 name["english"] = "SMTP too long line";
 script_name(english:name["english"]);
 
 desc["english"] = "
Some antivirus scanners dies when they process an email with a 
too long string without line breaks.
Such a message was sent. If there is an antivirus on your MTA,
it might have crashed. Please check its status right now, as 
it is not possible to do it remotely

";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a too long single line to the MTA";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("smtpserver_detect.nasl", "smtp_settings.nasl", "smtp_relay.nasl");
 script_require_ports("Services/smtp", 25);
 script_exclude_keys("SMTP/spam", "SMTP/wrapped");

 exit(0);
}

# The script code starts here

include("smtp_func.inc");

# Disable the test if the server relays e-mails.
if (get_kb_item("SMTP/spam")) exit(0);

fromaddr = smtp_from_header();
toaddr = smtp_to_header();

port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(!get_port_state(port))exit(0);

b = string("From: ", fromaddr, "\r\n", "To: ", toaddr, "\r\n",	
	"Subject: Nessus test - ignore it\r\n\r\n",
	crap(10000), "\r\n");
n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (n > 0) security_note(port);
