#
# Copyright 2003 by Michel Arboi <arboi@alussinan.org>
#
# Changes by rd: Description.
#
# GNU Public Licence
#
#T

if(description)
{
 script_id(11716);
 script_version ("$Revision: 1.2 $");

 name["english"] = "Misconfigured Gnutella";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Gnutella servent service.

It seems that the root directory of the remote host is visible through 
this service. Confidential files might be exported.

Solution : disable this Gnutella servent or configure it correctly
Risk factor : High";

 
 script_description(english:desc["english"]);

 summary["english"] = "Detect sensitive files shared by Gnutella";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "gnutella_detect.nasl");
 script_require_ports("Services/gnutella", 6346);
 exit(0);
}

#

function gnutella_read_data(socket, message)
{
  local_var	len, i, r2;
  len = 0;
  for (i = 22; i >= 19; i --)
    len = len * 256 + ord(message[i]);
  if (len > 0)
    r2 = recv(socket: soc, length: len);
  return r2;
}

function gnutella_search(socket, search)
{
  local_var	MsgId, Msg, r1, r2;

  MsgId = rand_str(length: 16);
  Msg = raw_string(	MsgId,			# Message ID
			128,			# Function ID
			1,			# TTL
			0,			# Hops taken
			strlen(search)+3, 0, 
			0, 0,			# Data length (little endian)
			0, 0,			# Minimum speed (LE)
			search, 0);
  send(socket: socket, data: Msg);

# We might get Ping and many other Gnutella-net messages
# We just read and drop them, until we get our answer.
  while (1)
  {
    r1 = recv(socket: soc, length: 23);
    if (strlen(r1) < 23)
      return;
    r2 = gnutella_read_data(socket: socket, message: r1);
    if (ord(r1[16]) == 129 && substr(r1, 0, 15) == MsgId)
      return r2;
  }
}

#

include("misc_func.inc");

port = get_kb_item("Services/gnutella");
if (! port) port = 6346;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket:soc, data: 'GNUTELLA CONNECT/0.4\n\n');
r = recv(socket: soc, length: 13);
if (r != 'GNUTELLA OK\n\n')
{
  # security_note(port: port, data: 'This Gnutella servent rejected the connection: ' + r);
  close(soc);
  exit(0);
}

# GTK-Gnutella sends a ping on connection
r = recv(socket: soc, length: 23);
if (strlen(r) >= 23)
{
  r2 = gnutella_read_data(socket: soc, message: r);
  if (ord(r[16]) == 0)	# Ping
  {
    # Pong  (phony answer)
    MsgId = substr(r, 0, 15);
    ip = this_host();
    #display("ip=", ip, "\n");
    x = eregmatch(string: ip, pattern: "([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)");
    #display("ip=", x, "\n");
    Msg = raw_string(	MsgId,
			1,	# pong
			1,	# TTL
			0,	# Hop
			14, 0, 0, 0, 
			11, 11,			# Listening port
			int(x[1]), int(x[2]), int(x[3]), int(x[4]),	# IP
			1, 1, 0, 0, 	# File count (little endian)
			1, 1, 0, 0);	# KB count
   send(socket: soc, data: Msg);
  }
}

dangerous_file = 
	make_list("boot.ini", "win.ini", "autoexec.bat", 
	"config.sys", "io.sys", "msdos.sys", "pagefile.sys", 
	"inetd.conf", "host.conf");
foreach d (dangerous_file)
{
  r = gnutella_search(socket: soc, search: d);
  if (! isnull(r) && ord(r[0]) > 0)
  {
    close(soc);
    security_hole(port);
    exit(0);
  }
}

close(soc);
