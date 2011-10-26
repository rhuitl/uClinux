# Written by Michel Arboi <mikhail@nessus.org>
# GNU Public Licence
#

if(description)
{
  script_id(18373);
  script_version ("$Revision: 1.4 $");
  desc = "
The remote ident server returns random token instead of 
leaking real user IDs. This is a good thing.

Risk factor: None";

  script_name(english: "Detect slident and or fake identd");
  script_family(english: "Misc.");
  script_description(english:desc);
  script_summary(english: "Detect identd servers that return random tokens");
  script_category(ACT_GATHER_INFO);
  script_copyright(english: "This script is Copyright (C) 2005 Michel Arboi");
  script_require_ports("Services/auth", 113);
  script_dependencies("find_service1.nasl");
  exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');

iport = get_kb_item("Services/auth");
if(! iport) iport = 113;
if (! get_port_state(iport)) exit(0);

port = get_host_open_port();
if (! port) port = iport;

debug_print(level: 2, 'port=', port, ', iport=', iport);

j = 0;
for (i = 0; i < 3; i ++)	# Try more than twice, just in case
{
 soc = open_sock_tcp(port);
 if (soc)
 {
  req = strcat(port, ',', get_source_port(soc), '\r\n');
  isoc = open_sock_tcp(iport);
  if (isoc)
  {
   send(socket: isoc, data: req);
   id = recv_line(socket: isoc, length: 1024);
   if (id)
   {
    ids = split(id, sep: ':');
    if ("USERID" >< ids[1])
    {
     got_id[j ++] = ids[3];
     debug_print('ID=', ids[3], '\n');
    }
   }
   close(isoc);
  }
  close(soc);
 }
}

slident = 0;
if (j == 1)
{
 # This is slidentd
 if (got_id[0] =~ '^[a-f0-9]{32}$')
 {
  debug_print('slident detected on port ', iport, '\n');
  slident = 1;
 }
}
else
 for (i = 1; i < j; i ++)
  if (got_id[i-1] != got_id[i])
  {
   slident = 1;	# Maybe not slident, but a fake ident anyway
   debug_print('Ident server on port ', iport, ' returns random tokens: ',
	chomp(got_id[i-1]), ' != ', chomp(got_id[i]), '\n');
   break;
  }

if (slident)
{
  if ( report_verbosity > 1 ) security_note(port: iport);
  log_print('Ident server on port ', iport, ' is not usable\n');
  set_kb_item(name: 'fake_identd/'+iport, value: TRUE);
}

