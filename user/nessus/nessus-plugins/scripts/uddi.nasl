#
# Copyright 2002 by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#
#

if(description)
{
    script_id(11140);
    script_version ("$Revision: 1.14 $");
#   script_cve_id("CVE-MAP-NOMATCH");
    name["english"] = "UDDI detection";
    script_name(english:name["english"]);
    desc["english"] = "
The tested Web server seems to be friendly to UDDI requests.  
The server could be potentially offering web services
under some other directory (we only tested the web root directory)
    
Risk factor : Low";

    script_description(english:desc["english"]);
    summary["english"] = "Find UDDI";
    script_summary(english:summary["english"]);
    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
    family["english"] = "General";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes");
    script_require_ports("Services/www", 80);
    exit(0);
}

#
# The script code starts here
#




include("uddi.inc");
include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
mypath = "/";

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_FBUSINESS", path:mypath, key:"", name:"e");  #loop through ETAOIN?
soc = open_sock_tcp(port);

if(soc) 
{
  send(socket:soc, data:mymessage);
  getreply = http_recv(socket:soc);
  close(soc);
}
else
{
  exit(0);
}



mystr = strstr(getreply, "serviceKey");
if (!mystr) 
{
   soaptest = strstr(getreply,"soap:Envelope");
   if (soaptest) {
      mywarning = string("The server seems to accept UDDI queries.  This could indicate\n");
      mywarning = string(mywarning, " that the server is offering web services");
      security_warning(port:port, data:mywarning);
      }
    exit(0);
}

flag = 0;
mykey = "";
for (i=12; flag < 1 ; i = i + 1) 
{                        #jump over servicekey=
    if ( (mystr[i] < "#") && (mystr[i] > "!") ) # BLECH!
        flag = flag + 1;
   else 
   	mykey = string(mykey, mystr[i]);
    
}

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_GSERVICE_DETAIL", path:mypath, key:mykey);

soc = open_sock_tcp(port);
if (soc) 
{
   send(socket:soc, data:mymessage);
   getreply = http_recv(socket:soc);
}

if (egrep(pattern:mykey, string:getreply)) 
{
        mywarning = string("The server is accepting UDDI queries.  This indicates\n");
	mywarning = string(mywarning, " that the server is offering web services");
	security_warning(port:port, data:mywarning);
        exit(0);
}

if (egrep(pattern: ".*200 OK.*", string:getreply)) 
{
        mywarning = string("The server seems to accept UDDI queries.  This could indicate\n");
	mywarning = string(mywarning, " that the server is offering web services");
	security_warning(port:port, data:mywarning);
	exit(0);
}

