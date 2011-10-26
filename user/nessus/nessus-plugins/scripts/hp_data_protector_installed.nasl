#
# Josh Zlatin-Amishav (josh at ramat dot cc) 
# GPLv2
# 

  desc["english"] = "
Synopsis :

HP OpenView Data protector is running on the remote host.

Description :

HP OpenView Data Protector is a data management solution that automates 
backup and recovery.

See also : 

http://h18006.www1.hp.com/products/storage/software/dataprotector/

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";

  
if (description) {
  script_id(19601);
  script_version("$Revision: 1.6 $");

  name["english"] = "HP Data Protector Detection";
  script_name(english:name["english"]);
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Data Protector";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Josh Zlatin-Amishav");
  script_require_ports(5555);
  exit(0);
}

include ("misc_func.inc");

# The code ...

port = 5555;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
versionpat = 'Data Protector ([^:]+)';
buildpat   = 'internal build ([^,]+)';
if(soc)
{
  # Data Protector can take some time to return its header
  response = recv(socket:soc, length:4096, timeout:20);
  
  if ("HP OpenView Storage Data Protector" >< response)
  {
    versionmatches = egrep(pattern:versionpat, string:response);
    if (versionmatches)
    {
      foreach versionmatch (split(versionmatches))
      {
        versions = eregmatch(pattern:versionpat, string:versionmatch);
      }
    }
    buildmatches = egrep(pattern:buildpat, string:response);
    if (buildmatches)
    {
      foreach buildmatch (split(buildmatches))
      {
        builds = eregmatch(pattern:buildpat, string:buildmatch);
      }
    }
    
    if ((versions[1] == "") && (builds[1] == ""))
    {
      versions[1] = "unknown"; 
      builds[1]   = "unknown";
    }

    register_service (port:port, proto:"hp_openview_dataprotector");

    desc["english"] += string("\n\nPlugin output :\n\nHP OpenView Data Protector version: ", versions[1], " build: ", builds[1], " is installed.");
    security_note(port:port, data:desc["english"]);
    set_kb_item (name:"Services/data_protector/version", value:versions[1]);
    set_kb_item (name:"Services/data_protector/build", value:builds[1]);
  }
}
