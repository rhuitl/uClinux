#
# (C) Tenable Network Security:
#

 desc["english"] = "
Synopsis :

A message queuing service is running on the remote host.

Description :

The remote host is running the Computer Associate Message Queuing service
(CAM).
This service is available with products like Unicenter TNG, Unicenter NSM,
BrightStor SAN Manager.

Risk factor :

None";


if(description)
{
 script_id(20147);

 script_version ("$Revision: 1.4 $");
 name["english"] = "CA Message Queuing service";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Detects Compute Associates Message Queuing sevice";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english: "Service detection");
 script_require_ports(4105);
 exit(0);
}

include ("byte_func.inc");


function ascii ()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return l + '\0';
}


function raw_ip ()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if (!egrep (pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", string:l))
   return mkdword (0);

 l = split (l, sep:".", keep:FALSE);
 return mkbyte (int(l[0])) +
	mkbyte (int(l[1])) +	
	mkbyte (int(l[2])) +
	mkbyte (int(l[3]));
}

function cam_packet (data, code)
{
 local_var packet;

 packet = mkbyte (0xFA) +
          mkbyte (code) +
          mkword (strlen(data) + 4) +
          data;

 return packet;
}


function recv_cam (socket)
{
 local_var data, tmp, len, ret, packet, code;

 tmp = recv(socket:socket, length:1, min:1);
 if (isnull(tmp) || (ord(tmp[0]) != 0xFA))
   return NULL;

 code = recv(socket:socket, length:1, min:1);
 if (isnull(code))
   return NULL;

 len = recv(socket:socket, length:2, min:2);
 if (isnull(code))
   return NULL;

 len = getword (blob:len,pos:0);
 len = len-4;
 if ((len > 65535) || (len < 12))
   return NULL;

 data = recv (socket:socket, length:len, min:len);
 if (strlen(data) != len)
   return NULL;

 ret = NULL;
 ret[0] = ord(code[0]);
 ret[1] = data;

 return ret;
}


function cam_status_request (socket)
{
 local_var data, packet, buf, local_ip, remote_ip, ret;

 ret = NULL;

 local_ip = this_host();
 remote_ip = get_host_ip();

 # try 3 times if the random number is used.
 # the function will return before that is success or if the server does nor reply

 for (i=0; i<3; i++)
 {
  data = mkdword (rand()) +
         mkdword (rand()) +
         raw_ip (local_ip) +
         raw_ip (remote_ip) +
         ascii ("SR") +
         mkbyte (4) +
         mkbyte (1) +
         mkbyte (0) +
         ascii (local_ip) +
         ascii ("CAI544E53-00000") +
         ascii (remote_ip) +
         ascii ("cam") +
         mkbyte (0xAF);

  packet = cam_packet (data:data, code:0x0D);

  send (socket:socket, data:packet);
  buf = recv_cam (socket:socket);
 
  if (isnull (buf) || (buf[0] != 0xFF) || (strlen(buf[1]) != 12))
    return ret;

  while (1)
  {
   buf = recv_cam (socket:socket);

   if (!isnull (buf))
   {
    # ACK reply
    data = substr(buf[1], 0, 11);
    packet = cam_packet (code:0xFF, data:data);
    send (socket:socket, data:packet);

    if (strlen(buf[1] <= 22))
      return ret;

    rep = substr(buf[1], 16, 17);

    if ((buf[0] == 0x91) && (rep == "HD"))
    {
     buf = substr(buf[1], 22, strlen(buf[1])-1);

     buf = split (buf, sep:'\0', keep:FALSE);
     if (max_index(buf) == 5)
       ret = buf[4];
    }

    if (rep == "OK")
      return ret;
   }
  }

  if (!isnull(ret))
    return ret;
 }

 return ret;
}


function cam_quit_request (socket)
{
 local_var data, packet;

 data = crap(data:mkbyte(0), length:12);
 packet = cam_packet (code:0xFC, data:data);
 send (socket:socket, data:packet);
}


function check(port)
{
 local_var soc, buf, ret, req, rep;

 ret = 0;

 soc = open_sock_tcp (port);
 if (!soc)
   exit(0);

 buf = recv (socket:soc, length:4, min:4);
 if (buf == 'ACK\0')
 {
  ret = 1;
  buf = cam_status_request (socket:soc);
  if (egrep (string:buf, pattern:"^[0-9]+\.[0-9]+ \(Build [0-9]+_[0-9]+\).*"))
  {
   version = ereg_replace (string:buf, pattern:"^([0-9]+\.[0-9]+ \(Build [0-9]+_[0-9]+\)).*", replace:"\1");
   set_kb_item (name:"CA/MessageQueuing", value:version);

   report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote version of CAM service is : ",
		version);

   security_note(port:port, data:report);
  }

  # Packet : QUIT
  cam_quit_request (socket:soc);
 }

 close (soc);

 return ret;
}

port = 4105;

if (!get_port_state(port))
  exit (0);


# run the check time because sometimes the server close the connection
# before the first 'ACK\0'

ret = check (port:port);
if (ret == 0)
  check (port:port);
