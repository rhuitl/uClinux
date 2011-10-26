#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

An unpassword Database server is listening on the remote port.

Description :

The remote host is running MySQL, an open-source Database server. It
is possible to connect to the remote database using one of the following
unpassworded account :

- root
- anonymous

It may allow an attacker to launch further attacks against the database.

Solution :

Disable anonymous account or set a password for root account.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10481);  
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-2004-1532");
 script_bugtraq_id(11704);

 name["english"] = "MySQL Remote Insecure Default Password Vulnerability";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "Checks Default unpassword MySQL accounts";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports("Services/mysql", 3306);
 script_dependencies("find_service.nes");
 exit(0);
}

include ("byte_func.inc");

global_var packet_number;

function parse_length_number (blob)
{
 return make_list (
		ord(blob[0]) + (ord(blob[1]) << 8) + (ord(blob[2]) << 16),
		ord(blob[3])
		);
}

function null_ascii (s)
{
 return s + mkbyte(0);
}

function mysql_packet (data)
{
 local_var len, tmp;

 len = strlen(data);
 tmp = raw_string (len & 0xFF,  (len>>8) & 0xFF, (len>>16) & 0xFF, packet_number) + data;
 packet_number++;

 return tmp;
}

function mysql_auth_req (name)
{
 return mkword (0x05a4)             + # Flags
        mkbyte (0) + mkword (0)     + # Max packet
        null_ascii (s:name);
}

function mysql_query (query)
{
 return mkbyte(3) + query;

}

function mysql_show_databases_request (socket)
{
 local_var req, buf, databases, loop;

 packet_number = 0;
 req = mysql_packet (data:mysql_query(query:"show databases"));

 databases = make_list ();

 send (socket:socket, data:req);
 buf = recv_mysql_packet (socket:socket);
 if (!isnull(buf) && (getbyte (blob:buf, pos:0) == 1))
 {
  buf = recv_mysql_packet (socket:socket);
  if (!isnull(buf))
  {
   buf = recv_mysql_packet (socket:socket);
   if (!isnull(buf) && (getbyte(blob:buf, pos:0) == 254))
   {
    loop = 1;
    while (loop)
    {
     buf = recv_mysql_packet (socket:socket);
     if (!isnull(buf) && (getbyte(blob:buf, pos:0) != 254))
       databases = make_list (databases, substr(buf, 1, strlen(buf)-1));
     else
       loop = 0;
    }
   }
  }    
 }

 if (max_index(databases) > 0)
   return databases;
 else
  return NULL;
}

function recv_mysql_packet (socket)
{
 local_var len, packet_info, buf;

 len = recv (socket:socket, length:4, min:4);
 if (strlen (len) != 4)
   return NULL;

 packet_info = parse_length_number (blob:len);

 if ((packet_info[0] > 65535) || (packet_info[1] != packet_number))
   return NULL;

 packet_number ++;

 buf = recv (socket:socket, length:packet_info[0], min:packet_info[0]);
 if (strlen(buf) != packet_info[0])
   return NULL;

 return buf;
}


## Main code ##

port = get_kb_item("Services/mysql");
if (!port)
  port = 3306;

if (!get_port_state(port))
  exit (0);


foreach name (make_list("root", "anonymous"))
{
 packet_number = 0;

 soc = open_sock_tcp (port);
 if (!soc)
   exit (0);

 buf = recv_mysql_packet (socket:soc);
 if (isnull(buf) || (getbyte(blob:buf, pos:0) != 10))
   exit (0);

 req = mysql_packet (data:mysql_auth_req (name:name));

 send (socket:soc, data:req);
 buf = recv_mysql_packet (socket:soc);
 if (isnull(buf))
   exit (0);

 error_code = getbyte (blob:buf, pos:0);
 if (error_code == 0)
 {
  databases = mysql_show_databases_request (socket:soc);

  if (!isnull(databases))
  {
   report = NULL;
   foreach value (databases)
   {
    report += string (value, "\n");
   }

    report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"Using the unpassword account '", name, "' it was possible to get the database list :\n\n",
		report);

    security_hole (port:port, data:report);
    exit (0);
  }
 
  security_hole (port);
  exit(0);
 }

 close (soc);
}
