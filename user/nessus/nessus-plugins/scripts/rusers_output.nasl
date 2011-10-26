#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Nothing really new - I just realized that Nessus won't show the
# output of rusers, so I added this plugin.
#

if(description)
{
 script_id(11058);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-1999-0626");
 
 name["english"] = "rusersd output";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script connects to the remote rusers server
and attempts to extract the list of users currently
logged in the remote host.";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

include("misc_func.inc");


# rusersd is only on top of UDP (AFAIK)
port = get_rpc_port(program:100002, protocol:IPPROTO_UDP);
if(!port)exit(0);

soc = open_sock_udp(port);

req = raw_string(0x25, 0xC8, 0x20, 0x4C, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		 0x86, 0xA2, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
		 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00);

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
close(soc);
if(strlen(r) > 28)
{
  num_entries = ord(r[27]);
  if(num_entries == 0)
  {
    report = string("Using rusers, we could determine that no one is currently logged on the\n", "remote host.\n");
    security_note(data:report, port:port, proto:"udp");
    exit(0);
  }

  report = string("Using rusers, we could determine that the following users are logged in :\n");
  start = 32;
  for(i=0; i < num_entries ; i = i + 1)
  {
    tty = "";
    len = 0;
    for(j = start ; ord(r[j]) && len < 16 ; j = j + 1)
    {
       if(j > strlen(r))exit(0);
       tty = string(tty, r[j]);
       len = len + 1;
    }

   start = start + 12;
   user = "";
   len = 0;
   for(j = start ; ord(r[j]) &&  len < 16; j = j + 1)
   {
     if(j > strlen(r))exit(0);
     user = string(user, r[j]);
     len = len + 1;
   }
   start = start + 12;
   from = "";
   len  = 0;
   for(j = start ; ord(r[j]) && len < 16 ; j = j + 1)
   {
     len = len + 1;
     if(j > strlen(r))exit(0);
     from = string(from, r[j]);
   }
   
   start = start + 28;
   report = string(report, "\n  - ", user, " (", tty, ")");
   if(strlen(from))report = string(report, " from ", from);
  }

  report = string(report, "\n\nSolution : disable this service.\n", 
      		"Risk factor : Low");

  security_note(data:report, port:port, proto:"udp");
}
