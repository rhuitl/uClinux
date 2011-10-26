# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL
#

if(description)
{
 script_id(18391);
 script_version ("$Revision: 1.4 $");
 name["english"] = "SMTP server on a strange port";
 script_name(english:name["english"]);
 
 desc = "This SMTP server is running on a non standard port. 
This might be a backdoor set up by crackers to send spam
or even control your machine.

Solution: Check and clean your configuration
Risk factor : Medium";

 script_description(english:desc);
 script_summary(english: "An SMTP server is running on a non standard port");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Backdoors");

 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

port = get_kb_item("Services/smtp");
if (port && port != 25 && port != 465 && port != 587) security_warning(port);
