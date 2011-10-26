#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

An SMTP server is listening on the remote port.

Description :

The remote host is running a mail (SMTP) server on this port.

Since SMTP servers are the targets of spammers, it is recommended you 
disable it if you do not use it.

Solution : 

Disable this service if you do not use it, or filter incoming traffic 
to this port.

Risk factor : 

None";

if(description)
{
 script_id(10263);
 script_version ("$Revision: 1.44 $");
 name["english"] = "SMTP Server Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "SMTP Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl", "check_smtp_helo.nasl", "smtpscan.nasl");
 script_require_ports("Services/smtp", 25);
 
 exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if ( ! port ) port = 25;
if ( ! get_port_state(port) ) exit(0);

banner = get_smtp_banner(port:port);
if ( banner && banner =~ "^220" )
 {
   report = desc["english"] + '\n\nPlugin output :\n\nRemote SMTP server banner :\n' + banner;
   security_note(port:port, data:report);
 }
