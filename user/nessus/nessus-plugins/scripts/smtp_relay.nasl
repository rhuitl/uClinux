#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10262);
 script_bugtraq_id(6118, 7580, 8196);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-1999-0512", "CVE-2002-1278", "CVE-2003-0285");
 name["english"] = "Mail relaying";
 name["francais"] = "Relais de mail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
 The remote SMTP server seems to allow the relaying. This means that
it allows spammers to use your mail server to send their mails to
the world, thus wasting your network bandwidth.

Risk factor : Low / Medium

Solution : configure your SMTP server so that it can't be used as a relay
           any more.";


 desc["francais"] = "
Le serveur SMTP distant semble permettre le relaying. C'est à dire
qu'il permet aux spammeurs de l'utiliser pour envoyer leurs mails au monde 
entier, gachant ainsi votre bande passante.

Facteur de risque : Faible/Moyen

Solution : Reconfigurez votre serveur SMTP afin qu'il ne puisse plus etre
utilisé comme relais.";


 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used as a spam relay"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé comme relais de spam";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl",
		"smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('network_func.inc');
include("smtp_func.inc");

if (is_private_addr()) exit(0);

function smtp_test_relay(tryauth)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 if (!data) 
 {
  close(soc);
  exit(0);
 }
 domain = get_kb_item("Settings/third_party_domain");
 
 crp = string("HELO ", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);

 if(tryauth)
 {
  crp = string("AUTH CRAM-MD5\r\n");
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);

  crp = string("ZnJlZCA5ZTk1YWVlMDljNDBhZjJiODRhMGMyYjNiYmFlNzg2Z==\r\n");
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);
 }

 crp = string("MAIL FROM: <test_1@", domain, ">\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);

 crp = string("RCPT TO: <test_2@", domain, ">\r\n");
 send(socket:soc, data:crp);
 i = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:i))
  {
  send(socket:soc, data:string("DATA\r\n"));
  r = recv_line(socket:soc, length:1024);
  if(ereg(pattern:"^[2-3][0-9][0-9] .*", string:r))
   {
   security_warning(port);
   set_kb_item(name:"SMTP/spam", value:TRUE);
   set_kb_item(name:"SMTP/" + port + "/spam", value:TRUE);
   }
  }
 close(soc);
}

# can't perform this test on localhost
if(islocalhost())exit(0);

# can't perform this test on the local net
#if(islocalnet())exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(get_port_state(port))
{
  if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
  smtp_test_relay(tryauth: 0);
  smtp_test_relay(tryauth: 1);
}
