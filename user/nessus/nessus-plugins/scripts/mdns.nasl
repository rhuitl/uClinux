#
# (C) Tenable Network Security
#
if(description) {
 script_id(12218);
 script_version("$Revision: 1.7 $");

 name["english"] = "mDNS Detection";
 script_name(english:name["english"]);

 desc["english"] ="
The remote host is running RendezVous (also known as ZeroConf or mDNS).
This service allows users on the network to enumerate information about the
remote host, such as the list of services it is running, its host name and
more.

An attacker may use this information to perform a more accurate attack.

Solution : filter incoming traffic to UDP port 5353
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "mDNS detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#


include("byte_func.inc");
include("dns_func.inc");

port = 5353;
if(!get_udp_port_state(port))exit(0);

seen_mdns = 0;

# Many Windows-PC have iTunes installed, so we attempt to detect it
domain[0] = string("_daap");      dsz[0] = strlen(domain[0]);
domain[1] = string("_tcp");   dsz[1] = strlen(domain[1]);
domain[2] = string("local");      dsz[2] = strlen(domain[2]);

req = raw_string(
0x00,0x4a,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
req += raw_string(0x00,0x00,0x0c,0x00,0x01);

soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096, timeout:2);
if ( r ) seen_mdns ++;



# MacOS only
domain[0] = string("_workstation");      dsz[0] = strlen(domain[0]);
domain[1] = string("_tcp");   dsz[1] = strlen(domain[1]);
domain[2] = string("local");      dsz[2] = strlen(domain[2]);



# Step[0] let's try to insert this value into the cache 
req = raw_string(
0x00,0x4a,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
req += raw_string(0x00,0x00,0x0c,0x00,0x01);

send(socket:soc, data:req);
r = recv(socket:soc, length:4096, timeout:3);
if ( strlen(r) > 6 ) answers = (ord(r[6]) * 256) + ord(r[7]);
else answers = 0;
if ( ! r || answers == 0 ){ 
 if ( seen_mdns )
 {
  security_note(port:port,
	      proto:"udp",
	      data:
"The remote host is running RendezVous (also known as mDNS or ZeroConf). 
Although it is not possible to extract information about the remote host,
you should disable this service if you do not use it.

Risk factor : Low");
	      
 }
 exit(0);
}


if ( strlen(r) > 53 )
{
 contents = dns_split(r);
 full_name = dns_str_get(str:contents["an_rr_data_0_data"], blob:r);
 ethernet = ereg_replace(pattern:".*\[(.*)\].*", string:full_name, replace:"\1");
 name     = ereg_replace(pattern:"(.*) \[.*", string:full_name, replace:"\1");


 
 for ( i = 0 ; i < 4 ; i ++ )
 {
  if  ( contents["ad_rr_data_" + i + "_type"]  == 0x0021 ) 
	{
	 target = contents["ad_rr_data_" + i + "_data"];
	 target = substr(target, 6, strlen(target) - 1);
         name =   dns_str_get(str:target, blob:r); 
	 got_better_name ++;
	}
 }

 set_kb_item(name:"mDNS/name", value:name);
 set_kb_item(name:"mDNS/ethernet", value:ethernet);

 if ( ! got_better_name ) name += '.local.';


 # Now, query the host info

 array = split(name, sep:'.', keep:FALSE);
 for ( i = 0 ; i < max_index(array) ; i ++ )
 {
  domain[i] = array[i];
  dsz[i]    = strlen(domain[i]);
 }

 domain[i] = NULL;



 req = raw_string(
0x00,0x4A,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
 for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
 req += raw_string(0x00,0x00,0x0d,0x00,0x01);

 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 if ( strlen(r) > 7 ) answers = (ord(r[6]) * 256) + ord(r[7]);
 close(soc);
 if ( answers == 0 )  exit(0); 

len = ord(r[12]);

offset = 13 + len + 23;
cpu_len = ord(r[offset]);
cpu_type = substr(r, offset + 1, offset + cpu_len);
set_kb_item(name:"mDNS/cpu", value:cpu_type);

offset += cpu_len + 1;
os = substr(r, offset + 1, offset + ord(r[offset]));
p = strstr(os, " (");
if ( p ) os -= p;

set_kb_item(name:"mDNS/os", value:os);


security_note(proto:"udp",
port:port, 
data:"
The remote host is running the RendezVous (also known as ZeroConf or mDNS)
protocol.

This protocol allows anyone to dig information from the remote host, such
as its operating system type and exact version, its hostname, and the list
of services it is running.

We could extract the following information :

Computer name    : " + name + "
Ethernet addr    : " + ethernet + "
Computer Type    : " + cpu_type + "
Operating System : " + os + "

Solution : You should filter incoming traffic to this port if you do not use 
this protocol.

Risk factor : Low");
}

