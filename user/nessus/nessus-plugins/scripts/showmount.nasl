#
# Get the export list of the remote host and 
# warns the user if a NFS share is exported to the
# world.
#
# Written by Renaud Deraison <deraison@cvs.nessus.org>
#
#

if(description)
{
 script_id(10437);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0554", "CVE-1999-0548");
 
 name["english"] = "NFS export";
 name["francais"] = "Export NFS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin retrieves the list of NFS exported shares,
and issues a red alert if some of them are world readable.

It also warns the user if the remote NFS server is superfluous.

Risk factor : Low / Medium";

 desc["francais"] ="
Ce plugin lit la liste des partitions NFS exportés, et
cause une alerte si certaines sont montables par le monde entier.

Il prévient aussi l'utilisateur si un daemon NFS superflu 
tourne";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for NFS";
 summary["francais"] = "Vérifie les partitions NFS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}




include("misc_func.inc");

#----------------------------------------------------------------------------#
#                              Here we go                                    #
#----------------------------------------------------------------------------#

security_problem = 0;
list = "";
number_of_shares = 0;
port = get_rpc_port(program:100005, protocol:IPPROTO_TCP);
soc = 0;
if(port)
{
 soc = open_priv_sock_tcp(dport:port);
 proto = "tcp";
}
else 
{
 proto = "udp";
 port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
 if(port) soc = open_priv_sock_udp(dport:port);
 else exit(0);
}
  
   
  if(soc)
  {
   req = raw_string(0x80, 0x00, 0x00, 0x28, 0x85, 0x80, 0x41, 0xEF, 0x00, 0x00,
   		    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		    0x86, 0xA5, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		    0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00);
   send(socket:soc, data:req);
   r = recv(socket:soc, length:8192);
   if(strlen(r) > 31)
   {
    value = ord(r[31]);
    start = 32;
    while(value)
     {
     length = ord(r[start]);
     length = ord(r[start+1])+length*256;
     length = ord(r[start+2])+length*256;
     length = ord(r[start+3])+length*256;
     directory = "";
     for(i=0;i<length;i=i+1)
     {
      directory = directory + r[start+4+i];
     }
     align = 4 - length % 4;
     if (align == 4)align = 0;
     nxt_group = ord(r[start+length+4+3+align]);
     if(!nxt_group)nogroup = 1;
     else nogroup = 0;
     start = start + length + 4 + 4 + align;
     groups="";
     while(nxt_group)
     {
      group_len = ord(r[start]);
      group_len = ord(r[start+1]) + group_len*256;
      group_len = ord(r[start+2]) + group_len*256;
      group_len = ord(r[start+3]) + group_len*256;
      g = "";
      for(i=0;i<group_len;i=i+1)
      {
       g = string(g, r[start+4+i]);
      }
      if(g == "*")security_problem = 1;
      groups = groups + g;
      groups = groups + ", ";
      align = 4 -  group_len % 4;
      if (align == 4)align = 0;
      nxt_group = ord(r[start+4+group_len+3+align]);
      if(nxt_group)start = start + 4 + group_len + 4 + align;
      else start = start + 8 + group_len + align;
     }
    if(nogroup){
    	groups = "(mountable by everyone)";
    	security_problem = 1;
	}
    value = ord(r[start+3]);
    start = start + 4;
    list = list + directory + " " + groups + string("\n");
    set_kb_item(name:"nfs/exportlist", value:directory);
    number_of_shares = number_of_shares + 1;
   }
 if(number_of_shares)
 {
  report = string("Here is the export list of ", get_host_name(), " : \n");
  report = report + list;
  security_note(port:2049, data:report, proto:proto);
  exit(0);
 }
 else
   {
    report = string("You are running a superfluous NFS daemon.\n", 
 		 "You should consider removing it\n"); 
    security_note(port:2049, data:report, proto:proto);
    exit(0);
   }		  
  }
  else
   {
    report = string("You are running a superfluous NFS daemon.\n", 
 		 "You should consider removing it\n"); 
    security_note(port:2049, data:report, proto:proto);
   }
}
