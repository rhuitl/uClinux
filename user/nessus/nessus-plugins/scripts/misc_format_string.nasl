#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# Date:	 Wed, 20 Mar 2002 11:35:04 +0100 (CET)
# From:	"Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# CC: security@isec.pl
# Subject: Bypassing libsafe format string protection
# 
# TBD: Add those tests:
#	printf("%'n", &target);
#	printf("%In", &target);
#	printf("%2$n", "unused argument", &target);
#


if(description)
{
 script_id(11133);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "Generic format string";
 name["francais"] = "Attaque 'format string' générique";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote service is vulnerable to a format string attack
An attacker may use this flaw to execute arbitrary code on this host.


Solution : upgrade your software or contact your vendor and inform it of this 
vulnerability
See also : http://www.securityfocus.com/archive/1/81565
Risk factor : High";


 desc["francais"] = "
Le service distant est vulnérable à une attaque 'format string'.

Un pirate peut exploiter cette faille pour exécuter du code quelconque
sur votre machine.

Solution: mettez à jour votre logiciel ou contactez votre 
vendeur et informez-le de cette vulnérabilité.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Generic format string attack";
 summary["francais"] = "Attaque format string générique";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/unknown");
 exit(0);
}

#

include('misc_func.inc');

port = get_unknown_svc();
if (! port) exit(0);


if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: "xxxxxxxxxxxxxxxxxxxxxxxxxx");
r1 = recv(socket: soc, length: 256, min:1);
close(soc);

flag = 1;
if (egrep(pattern:"[0-9a-fA-F]{4}", string: r1)) flag = 0;



soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, 
	data: crap(data:"%#0123456x%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x",
		length:256) );
r2 = recv(socket: soc, length: 256, min:1);
close(soc);


soc = open_sock_tcp(port);
if (! soc)
{
  security_hole(port);
  exit(0);
}

close(soc);

if (flag && (egrep(pattern:"[0-9a-fA-F]{4}", string: r2)))
{
  security_warning(port);
  exit(0);
}



