#
# This script was written by Paul Ewing <ewing@ima.umn.edu>
#
# See the Nessus Scripts License for details
#

if(description) {
    script_id(10462);
 script_version ("$Revision: 1.11 $");
 
    name["english"] = "Amanda client version";
    script_name(english:name["english"]);
 
    desc["english"] = "This detects the Amanda backup system client
version. The client version gives potential attackers additional
information about the system they are attacking.

Risk factor : Low";

    script_description(english:desc["english"]);
 
    summary["english"] = "Detect Amanda client version";
    script_summary(english:summary["english"]);
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2000 Paul J. Ewing Jr.");
    family["english"] = "Service detection";
    script_family(english:family["english"]);
    exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

function get_version(soc, port, timeout)
{
  local_var result, temp, version, data;

    if ( ! isnull(timeout) )
     result = recv(socket:soc, length:2048, timeout:timeout);
   else
     result = recv(socket:soc, length:2048);

    if (result) {
        if (egrep(pattern:"^[^ ]+ [0-9]+\.[0-9]+", string:result)) {
	    temp = strstr(result, " ");
            temp = temp - " ";
            temp = strstr(temp, " ");
            version = result - temp;
            data = string("Amanda version: ", version);
            security_note(port:port, data:data, protocol:"udp");
            register_service(port:port, ipproto: "udp", proto:"amanda");
            set_kb_item(name:"Amanda/running", value:TRUE);
	}
    }
}

req = 'Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\nSERVICE ' + rand_str(length:8) + '\n';
soc1 = open_sock_udp(10080);
send(socket:soc1, data:req);
soc2 = open_sock_udp(10081);
send(socket:soc2, data:req);

get_version(soc:soc1, port:10080, timeout:NULL);
get_version(soc:soc2, port:10081, timeout:1);
