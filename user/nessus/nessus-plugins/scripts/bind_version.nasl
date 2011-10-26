#
# (C) Tenable Network Security
#



 desc["english"] = "
Synopsis :

It is possible to obtain the version number of the remote DNS server.

Description :

The remote host is running BIND, an open-source DNS server. It is possible
to extract the version number of the remote installation by sending
a special DNS request for the text 'version.bind' in the domain 'chaos'.

Solution :

It is possible to hide the version number of bind by using the 'version'
directive in the 'options' section in named.conf

Risk factor : 

None";

if(description)
{
 script_id(10028);
 script_version ("$Revision: 1.32 $");
 name["english"] = "Version of BIND";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a VERSION.BIND request";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("dns_server.nasl");

 exit(0);
}


include("dns_func.inc");
include("byte_func.inc");


if ( get_kb_item("DNS/udp/53") )
{
 dns["transaction_id"] = rand() & 0xffff;
 dns["flags"]	      = 0x0010;
 dns["q"]	      = 1;
 packet = mkdns(dns:dns, query:mk_query(txt:mk_query_txt("VERSION", "BIND"),type:0x0010, class:0x0003));
 soc = open_sock_udp(53);
 send(socket:soc, data:packet);
 r = recv(socket:soc, length:4096);
 close(soc);
 response  = dns_split(r);
 if ( isnull(response) ) exit(0);
 f = response["flags"];
 
 if (f  & 0x8000 && !( f & 0x0003 ) && ! isnull( get_query_txt(response["an_rr_data_0_data"]) ) ) 
 {
  set_kb_item(name:"bind/version", value:get_query_txt(response["an_rr_data_0_data"]));
  report = desc["english"] + '\n\nPlugin output:\n\nThe version of the remote BIND server is : ' + get_query_txt(response["an_rr_data_0_data"]);
  security_note(port:53, data:report);
 }
}
