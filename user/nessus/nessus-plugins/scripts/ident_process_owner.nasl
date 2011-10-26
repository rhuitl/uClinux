#
# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#

if(description)
{
 script_id(14674);
 script_version ("$Revision: 1.9 $");
 script_name(english: "Identd scan");
 
 desc = "
This plugin uses identd (RFC 1413) to determine which user is 
running each service

Risk factor : Low";

 script_description(english:desc);
 
 summary["english"] = "Get UIDs with identd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service1.nasl", "slident.nasl");
 script_require_ports("Services/auth", 113);
 #script_exclude_keys("Host/ident_scanned");
 exit(0);
}

if (! defined_func("get_source_port")) exit(0);

include("misc_func.inc");
include('global_settings.inc');

if (  thorough_tests ) max_pass = 6;
else max_pass = 3;

#if (get_kb_item("Host/ident_scanned")) exit(0);

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))
  if (COMMAND_LINE)
   for (i = 1; i <= 65535; i ++)
    ports[i] = "Ports/tcp/"+i;
  else
   exit(0);

# Should we only use the first found identd?

list = get_kb_list("Services/auth");
if ( ! isnull(list) ) 
     list = make_list(113, list);
else 
     list = make_list(113);

foreach iport ( list )
{
 if (get_port_state(iport) && ! get_kb_item('fake_identd/'+iport))
 {
  isoc = open_sock_tcp(iport);
  if (isoc) break;
 }
 else
  debug_print('Port ', iport, ' is closed or blacklisted\n');
}
if (! isoc) exit(0);
debug_print('iport=', iport, '\n');

# Try several times, as some ident daemons limit the throughput of answers?!
for (i = 1; i <= max_pass && ! isnull(ports); i ++)
{
 prev_ident_n = identd_n;
 j = 0;
 if (i > 1) debug_print('Pass #', i);
foreach port (keys(ports))
{
 if ( port == 139 || port == 445 ) continue;
 port = int(port - "Ports/tcp/");
 if (get_port_state(port) && ! get_kb_item("Ident/tcp"+port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   debug_print('Testing ', port, '\n');
   req = strcat(port, ',', get_source_port(soc), '\r\n');
   if (send(socket: isoc, data: req) <= 0)
   {
# In case identd does not allow several requests in a raw
    close(isoc);
    isoc = open_sock_tcp(iport);
    if (!isoc) { close(soc); exit(0); }
    send(socket: isoc, data: req);
   }
   id = recv_line(socket: isoc, length: 1024);
   debug_print('Identd(',port,')=', id);
   if (id)
   {
    ids = split(id, sep: ':');
    if ("USERID" >< ids[1] && strlen(ids[3]) < 30 )
    {
     identd_n ++;
     set_kb_item(name: "Ident/tcp/"+port, value: ids[3]);
     security_note(port: port, 
data: 'identd reveals that this service is running as user '+ids[3]);
    }
    else
     bad[j++] = port;
   }
   else
    bad[j++] = port;
  }
 }
}
 # Exit if we are running in circles
 if (prev_ident_n == identd_n) break;
 ports = NULL;
 foreach j (bad) ports[j] = j;
 bad = NULL;
}
if (-- i > 1) debug_print(i, ' passes were necessary');

close(isoc);
set_kb_item(name: "Host/ident_scanned", value: TRUE);

