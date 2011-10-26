#
#
# This script is (C) 2003 Renaud Deraison
#
#

if (description)
{
 script_id(11390);
 script_bugtraq_id(3958);
 script_cve_id("CVE-2002-0048");
 
 script_version ("$Revision: 1.9 $");
 script_name(english:"rsync array overflow");
 desc["english"] = "
The remote rsync server is vulnerable to an array index
overflow.

An attacker may use this flaw to gain a shell on this host

Solution : Upgrade to rsync 2.5.2 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if the remote rsync is buggy");
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
if(!welcome)exit(0);
if(!ereg(pattern:"@RSYNCD: (1[0-9]|2[0-5])[^0-9]", string:welcome)) exit(0);

send(socket:soc, data:string("@BOGUS\n"));
motd = NULL;

for(i=0;i<255;i++)
{
 r = recv_line(socket:soc, length:4096);
 if(!r || "@ERROR" >< r)break;
 else motd += r;
}

close(soc);

soc = rsync_init(port:port, motd:motd);
send(socket:soc, data:string("#list\r\n"));

modules = make_list();

for(i=0;i<1024;i++)
{
 module = recv_line(socket:soc, length:4096);
 if(!module)break;
 if("@RSYNC" >< module) break;
 mod = split(module, sep:" ");
 modules = make_list(modules, mod[0] - " ");
}
close(soc);


foreach module (modules)
{
 soc = rsync_init(port:port, motd:motd);
 if(soc != NULL)
 {
 send(socket:soc, data:string(module, "\n"));
 r = recv_line(socket:soc, length:4096);
 if("@RSYNCD: OK" >< r)
 {
  send(socket:soc, data:string("--server\n--sender\n\n"));
  r = recv(socket:soc, length:4);
  send(socket:soc, data:raw_string(0xFF,0xFF,0xFF,0xFF));
  send(socket:soc, data:string("\n\n\n\n"));
  r = recv_line(socket:soc, length:4096);
  if(r)security_hole(port);
  exit(0);
 }
 else close(soc);
 }
}

#
# Could not test anything...
# 


if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-5])[^0-9]", string:welcome))
{
 report = "
The remote rsync server seems to be vulnerable to 
an array index overflow. However, Nessus could not
verify this flaw as no module could be retrieved, so
so this might be a false positive.

Solution : Upgrade to rsync 2.5.2
Risk factor : High";

 security_hole(port:port, data:report);
}
