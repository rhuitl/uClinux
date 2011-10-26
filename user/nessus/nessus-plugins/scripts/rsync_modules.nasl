#
#
# This script is (C) 2003 Renaud Deraison
#
#

if (description)
{
 script_id(11389);
#script_cve_id("CVE-MAP-NOMATCH");
 
 script_version ("$Revision: 1.8 $");
 script_name(english:"rsync modules");
 desc["english"] = "
This plugin extracts the rsync modules available on the remote
host.

Risk factor : None";


 script_description(english:desc["english"]);
 script_summary(english:"Shows the remotely accessible rsync modules");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencies("find_service.nes");
 script_require_ports("Services/rsync", 873);
 exit(0);
}

function rsync_init(port, motd)
{
 local_var soc, r, q, i;
  
 soc = open_sock_tcp(port);
 if(!soc)return NULL;
 r = recv_line(socket:soc, length:4096);
 if(motd) q = recv(socket:soc,length:strlen(motd), min:strlen(motd));
 send(socket:soc, data:r);
 return soc;
}

port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

welcome = recv_line(socket:soc, length:4096);
send(socket:soc, data:string("@BOGUS\n"));
if(!welcome)exit(0);
motd = NULL;

set_kb_item(name:"rsync/" + port + "/banner", value:welcome);

for(i=0;i<1024;i++)
{
 r = recv_line(socket:soc, length:4096);
 if(!strlen(r) || "@ERROR" >< r)break;
 else motd += r;
} 
close(soc);

soc = rsync_init(port:port, motd:motd);
send(socket:soc, data:string("#list\r\n"));

modules = NULL;


for(i=0;i<255;i++)
{
 r = recv_line(socket:soc, length:4096);
 if(!r || "@RSYNC" >< r)break;
 modules += r;
}

close(soc);

if (modules != NULL )
{
  d = NULL;
  foreach module (split(modules))
  {
   m = split(module, sep:" ");
   soc = rsync_init(port:port, motd:motd);
   if(soc)
   {
    send(socket:soc, data:string(m[0]  - " ", "\r\n"));
    r = recv_line(socket:soc, length:4096);
    if("@RSYNCD: OK" >< r)d += (module  - string("\n") ) + string(" (readable by anyone)\n");
    else d += (module - string("\n")) + string(" (authentication required)\n");
    close(soc);
   }
  }

 report = NULL;
 
 if( motd != NULL )report = string(". The MOTD banner of the remote rsync server is :\n", motd, "\n");
 
 report += string(". The following rsync modules are available on the remote host :\n\n",
 d, 
 "\nMake sure that only the relevant persons have access to them\n");
 if("(readable by anyone)" >< report) security_hole(port:port, data:report);
 else security_note(port:port, data:report);
}
