# 
# (C) 2005 Tenable Network Security
#

if(description)
{
 script_id(14274);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Nessus SNMP Scanner";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs an SNMP scan against the remote machine to find open ports.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find open ports with Nessus SNMP Scanner";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Port scanners";
 script_family(english:family["english"]);

 script_dependencies("ping_host.nasl","snmp_settings.nasl");

 exit(0);
}


include ("snmp_func.inc");


#---------------------------------------------------------#
# Function    : issameoid                                 #
# Description : check if oid is in the item than oid      #
#---------------------------------------------------------#

function issameoid(origoid, oid)
{
 local_var tmp;

 if (strlen(oid) < strlen(origoid))
   return FALSE;

 tmp = substr(oid,0,strlen(origoid));

 if ( tmp != string(origoid,"."))
   return FALSE;

 return TRUE;
}


#---------------------------------------------------------#
# Function    : scan                                      #
# Description : do a snmp port scan with get_next_pdu     #
# Notes       : 'ugly' port check is due to solaris       #
#---------------------------------------------------------#

function scan(socket, community, oid, ip, val)
{
 local_var soid, pport_1, pport_2, port, pattern, port2, infos, list;

 list = make_list();

 soid = string (oid, ".", ip, ".0");
 pport_1 = -1; 
 pport_2 = -1;

 init_snmp ();

 while(1)
 {
  port = snmp_request_next (socket:socket, community:community, oid:soid);
  if (!isnull(port) && issameoid(origoid:oid, oid:port[0]))
  {
   # UDP
   pattern = string ("^",oid,"\\.(",ip,")\\.([0-9]+)$");
   if (egrep (pattern:pattern, string:port[0]))
   {
    port2 = ereg_replace (pattern:pattern, replace:"\1:\2", string:port[0]);
    infos = split (port2, sep:":", keep:0);
    if ( (infos[0] != ip) || (int(infos[1]) < int(pport_1)) )
      break;
   }
   else # TCP
   {
    pattern = string ("^",oid,"\\.(",ip,")\\.([0-9]+)\\.[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+)");
    port2 = ereg_replace (pattern:pattern, replace:"\1:\2:\3", string:port[0]);
    infos = split (port2, sep:":", keep:0);
    if ( (infos[0] != ip) || (int(infos[1]) < int(pport_1)) )
      break;
   }

   if (int(infos[1]) == int(pport_1))
   {
    soid = string (oid, ".", ip, ".", int(pport_1)+1);
   }
   else
   {
    if (isnull(val) || (port[1] == val))
    {
     list = make_list (list, int(infos[1]));
    }

    pport_1 = infos[1];
    pport_2 = infos[2];
    soid = port[0];
   }
  }
  else
    break;
 }

 return list;
}


#---------------------------------------------------------#
# Function    : scan_tcp                                  #
# Description : do a snmp tcp port scan                   #
#---------------------------------------------------------#

function scan_tcp (socket, community, ip)
{
 return scan (socket:socket, community:community, oid:"1.3.6.1.2.1.6.13.1.1", ip:ip, val:2);
}


#---------------------------------------------------------#
# Function    : scan_udp                                  #
# Description : do a snmp udp port scan                   #
#---------------------------------------------------------#

function scan_udp (socket, community, ip)
{
 return scan (socket:socket, community:community, oid:"1.3.6.1.2.1.7.5.1.2", ip:ip, val:NULL);
}



## Main code ##

snmp_comm = get_kb_item("SNMP/community");
if (!snmp_comm)
  exit (0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp (port);
if (!soc)
  exit (0);

# TCP scan
tcp_list = make_list (
             scan_tcp (socket:soc, community:snmp_comm, ip:"0.0.0.0"),
             scan_tcp (socket:soc, community:snmp_comm, ip:get_host_ip())
           );

# UDP
udp_list = make_list (
             scan_udp (socket:soc, community:snmp_comm, ip:"0.0.0.0"),
             scan_udp (socket:soc, community:snmp_comm, ip:get_host_ip())
           );


foreach tcp_port (tcp_list)
{
 scanner_add_port(proto:"tcp", port:tcp_port);
}

foreach udp_port (udp_list)
{
 scanner_add_port(proto:"udp", port:udp_port);
}

if (max_index(tcp_list))
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/full_scan", value: TRUE);
 set_kb_item(name: 'Host/scanners/snmp_scanner', value: TRUE);
 security_note(port: snmp_port, proto: snmp_layer, 
data: string("Nessus snmp scanner was able to retrieve the open port list with the community name ", snmp_comm));
}

if (max_index(tcp_list))
{
 set_kb_item(name: "Host/udp_scanned", value: TRUE);
}
