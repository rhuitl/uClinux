#TRUSTED 57a60a2091cc1f5a9c705d7996d647c1dbf2b7fbcfeb1937cc2b3b72cbcc8c6d34c05bafc6b18bb076a41b857f20e15237991a0ee653b8e546d45a00450b1377b06e9977ed77d7bc7170cf300a9183b109d2bb55227d7e4dfee239b97b93080f4e112e9ca210a3ab830126768e15f1d3e7895e623ace4fc41e60260f581cd84d3ba7b0a3adaa46766771c625bcf171c8537640a969ebf328ca04514edd6b3c74bc090925e47eb125d20b58fd540ed3b49e467f66a54f666a1e520bf34b56c834eefe88a4bcdacbf71d0dd7f69aa80908bbaa3f32de982564b86f97c3c96dcb0d1832342f54ec2f37bac4c1565c8ac725f7d1b28e95b7c7c1ba0d6b0d65bb9dc2b8b0c760c5663d754578723ed17346ccd1d9f93acd631b04cc54a903edef0f22763a92cad25d8a298702d4a4a4fd858aeb47d1db43a55bc576cf2f3f2291696ec60d637a98f9c8f6cd545d68f05674d0df93b28d92175f3aaefb31993f654a1236894d690414a18d763d7def7371c635fa9437708bae4f2d08c9130d9e2f90559893ec513810a09ec3c1e871b9582c29adfe46cd4a69485a7068b666182b9c3b638e4c82cdc1ab0aea95a97ea06bf65daf3e36e9e247d0a38db2a0bf199e9c48f97952d63a72be6dc9913df8268739151b5366445d9207f025c55513d7666e1a7609abaa21b1d8f79914d5d0e30be75fea2d4c3c537803f3805027045b365213
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

# No use to run this one if the other plugins cannot run!
if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15868);
 script_version ("1.1");
 name["english"] = "Hydra (NASL wrappers options)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin sets options for the Hydra(1) tests.
Hydra finds passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force authentication protocols";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");

 script_add_preference(name: "Logins file : ", value: "", type: "file");
 script_add_preference(name: "Passwords file : ", value: "", type: "file");
 script_add_preference(name: "Number of parallel tasks :", value: "16", type: "entry");
 script_add_preference(name: "Timeout (in seconds) :", value: "30", type: "entry");
 script_add_preference(name: "Try empty passwords", type:"checkbox", value: "no");
 script_add_preference(name: "Try login as password", type:"checkbox", value: "no");
 script_add_preference(name: "Exit as soon as an account is found", type:"checkbox", value: "no");
 script_add_preference(name: "Add accounts found by other plugins to login file",
	type:"checkbox", value: "yes");

 exit(0);
}

#

function mk_login_file(logins)
{
  local_var	tmp1,tmp2, dir, list, i, u;
  if ( NASL_LEVEL < 2201 ) return logins; # fwrite broken
  dir = get_tmp_dir();
  if (! dir) return logins;	# Abnormal condition
  for (i = 1; TRUE; i ++)
  {
    u = get_kb_item("SMB/Users/"+i);
    if (! u) break;
    list = strcat(list, u, '\n');
  }
# Add here results from other plugins
  if (! list) return logins;
  tmp1 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  tmp2 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  if (fwrite(data: list, file: tmp1) <= 0)	# File creation failed
    return logins;
  if (! logins) return tmp1;
  pread(cmd: "sort", argv: make_list("sort", "-u", tmp1, logins, "-o", tmp2));
  unlink(tmp1);
  return tmp2;
}


p = script_get_preference_file_location("Passwords file : ");
if (!p ) exit(0);
set_kb_item(name: "Secret/hydra/passwords_file", value: p);

# No login file is necessary for SNMP, VNC and Cisco; and a login file 
# may be made from other plugins results. So we do not exit if this
# option is void.
a = script_get_preference("Add accounts found by other plugins to login file");
p = script_get_preference_file_location("Logins file : ");
if ("no" >!< a) p = mk_login_file(logins: p);
set_kb_item(name: "Secret/hydra/logins_file", value: p);

p = script_get_preference("Timeout (in seconds) :");
t = int(p);
if (t <= 0) t = 30;
set_kb_item(name: "/tmp/hydra/timeout", value: t);

p = script_get_preference("Number of parallel tasks :");
t = int(p);
if (t <= 0) t = 16;
set_kb_item(name: "/tmp/hydra/tasks", value: t);

p = script_get_preference("Try empty passwords");
set_kb_item(name: "/tmp/hydra/empty_password", value: "yes" >< p);

p = script_get_preference("Try login as password");
set_kb_item(name: "/tmp/hydra/login_password", value: "yes" >< p);

p = script_get_preference("Exit as soon as an account is found");
set_kb_item(name: "/tmp/hydra/exit_ASAP", value: "yes" >< p);

