#
# This script was written by Michel Arboi <arboi@alussinan.org>
# Well, in fact I started from a simple script by Thomas Reinke and 
# heavily hacked every byte of it :-]
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# There was no information on the BugBear protocol. 
# I found a worm in the wild and found that it replied to the "p" command;
# the data look random but ends with "ID:"  and a number
# Thomas Reinke confirmed that his specimen of the worm behaved in the 
# same way. 
# We will not provide the full data here because it might contain 
# confidential information.
# 
# References:
#
# Date: Tue, 1 Oct 2002 02:07:29 -0400
# From:"Russ" <Russ.Cooper@RC.ON.CA>
# Subject: Alert:New worms, be aware of internal infection possibilities
# To:NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

if(description)
{
 script_id(11135);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0004");
 script_bugtraq_id(2524);
 script_cve_id("CVE-2001-0154"); # For MS01-020 - should be changed later
 script_version ("$Revision: 1.11 $");
 name["english"] = "Bugbear worm";
 name["francais"] = "Ver Bugbear";

 script_name(english:name["english"], francais: name["francais"]);
 
 desc["english"] = "
BugBear backdoor is listening on this port. 
A cracker may connect to it to retrieve secret 
information, e.g. passwords or credit card numbers...

The BugBear worm includes a key logger and can kill 
antivirus or personal firewall softwares. It propagates 
itself through email and open Windows shares.
Depending on the antivirus vendor, it is known as: Tanatos, 
I-Worm.Tanatos, NATOSTA.A, W32/Bugbear-A, Tanatos, W32/Bugbear@MM, 
WORM_BUGBEAR.A, Win32.BugBear...

http://www.sophos.com/virusinfo/analyses/w32bugbeara.html
http://www.ealaddin.com/news/2002/esafe/bugbear.asp
http://securityresponse.symantec.com/avcenter/venc/data/w32.bugbear@mm.html
http://vil.nai.com/vil/content/v_99728.htm

Reference : http://online.securityfocus.com/news/1034
Reference : http://support.microsoft.com/default.aspx?scid=KB;en-us;329770&

Solution: 
- Use an Anti-Virus package to remove it.
- Close your Windows shares
- Update your IE browser 
  See 'Incorrect MIME Header Can Cause IE to Execute E-mail Attachment'
  http://www.microsoft.com/technet/security/bulletin/MS01-020.mspx

Risk factor : Critical";

 desc["francais"] = "
La backdoor BugBear écoute sur ce port.
Un pirate peut se connecter dessus pour retrouver des informations
secrètes, par exemple des mots de passe ou des numéros de carte de
crédit...

Le ver BugBear inclut un 'key logger' et peut tuer les logiciels
antivirus ou firewalls personnels. Il se propage via le courrier
électronique ou les partages Windows ouverts.
Selon le vendeur d'antivirus, il est aussi nommé : Tanatos, 
I-Worm.Tanatos, NATOSTA.A, W32/Bugbear-A, Tanatos, W32/Bugbear@MM, 
WORM_BUGBEAR.A, Win32.BugBear...

http://www.sophos.com/virusinfo/analyses/w32bugbeara.html
http://www.ealaddin.com/news/2002/esafe/bugbear.asp
http://securityresponse.symantec.com/avcenter/venc/data/w32.bugbear@mm.html
http://vil.nai.com/vil/content/v_99728.htm

Solution: 
- Utilisez un antivirus pour le supprimer.
- Fermez vous partages Windows
- Mettez à jour votre navigateur IE 
  Cf. 'Incorrect MIME Header Can Cause IE to Execute E-mail Attachment'
  http://www.microsoft.com/technet/security/bulletin/MS01-020.mspx

Risk factor : Critical";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detect Bugbear worm";
 summary["francais"] = "Détecte le ver Bugbear";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(
  english:"This script is Copyright (C) 2002 Michel Arboi & Thomas Reinke",
  francais:"Ce script est copyright (C) 2002 Michel Arboi & Thomas Reinke");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(36794);
 script_dependencies("find_service.nes");
 exit(0);
}

#
include("misc_func.inc");

port = 36794;

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

# We just need to send a 'p' without CR
send(socket: soc, data: "p");
# I never saw a buffer bigger than 247 bytes but as the "ID:" string is 
# near the end, we'd better use a big buffer, just in case
r = recv(socket: soc, length: 65536);
close(soc);

if ("ID:" >< r) {
 security_hole(port); 
 register_service(port: port, proto: "bugbear");
 exit(0); 
}

msg = "
This port is usualy used by the BugBear backdoor.
Although Nessus was unable to get an answer from the worm, 
you'd better check your machine with an up to date 
antivirus scanner.

Risk factor: Medium";
security_warning(port: port, data: msg);

