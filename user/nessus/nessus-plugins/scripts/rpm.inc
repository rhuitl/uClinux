#
# (C) Tenable Network Security
#
# $Id: rpm.inc,v 1.12 2006/07/03 20:10:42 renaud Exp $



function parse_rpm_name(rpm, yank)
{
 local_var elems, num, i, name;
 local_var my_rpm;

 elems = split(rpm, sep:"|", keep:0);
 if ( max_index(elems) > 1 )
 {
  my_rpm["epoch"] = elems[1];
#  my_rpm["keyid"] = elems[2];
  rpm = elems[0];
 }
 elems = split(rpm, sep:"-", keep:0);
 num = max_index(elems);
 name = elems[0];
 for ( i = 1; i < num - 2 ; i ++ )
 {
  name += "-" + elems[i];
 }

 
 my_rpm["name"]     = name;
 my_rpm["version"]  = elems[num - 2];
 my_rpm["release"] = elems[num - 1];

 if ( yank ) {
	my_rpm["version"]  -= yank;
        my_rpm["release"] -= yank;
        my_rpm["epoch"] -= yank;
 }

 return my_rpm;
}


function vers_cmp(a, b)
{
 local_var array_a, array_b, i, max;


 array_a = split(a, sep:".", keep:0);
 array_b = split(b, sep:".", keep:0);
 
 if ( max_index(array_b) < max_index(array_a))
	max = max_index(array_a);
 else
	max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  if ( max_index(array_a) <= i ) return -1;
  if ( max_index(array_b) <= i ) return 1;

  if ( array_a[i] =~ "^[0-9]+$" || array_b[i] =~ "^[0-9]+$" )
      {
       if ( int(array_a[i]) != int(array_b[i]) )
         return int(array_a[i]) - int(array_b[i]);
      }
  else if ( array_a[i] != array_b[i] )
     {
        if ( array_a[i] < array_b[i] )
	  return -1;
 	else 
	  return  1;
     }
 }

 return 0;
}


function rpm_cmp(rpm, reference, yank, epoch)
{
 local_var my_rpm, my_reference, eq, ep;

 my_rpm = parse_rpm_name(rpm:rpm, yank:yank);
 my_reference = parse_rpm_name(rpm:reference, yank:yank);

 if ( epoch )
  {
  eq = int(my_rpm["epoch"]) - int(epoch);
  if ( eq  ) return eq;
  }

 eq = vers_cmp(a:my_rpm["version"], b:my_reference["version"]);
 if ( eq ) return eq;
 
 return vers_cmp(a:my_rpm["release"], b:my_reference["release"]);
}


function rpm_check(prefix, reference, yank, release, epoch, cpu)
{
 local_var rh_release, rpms, package, lines, e, my_rpm, ok, suse_release, mdk_release, centos_release;
 local_var my_cpu;

 rh_release = get_kb_item("Host/RedHat/release");
 suse_release = get_kb_item("Host/SuSE/release");
 mdk_release = get_kb_item("Host/Mandrake/release");
 centos_release = get_kb_item("Host/CentOS/release");

 if ( ! isnull(cpu) )
 {
  my_cpu = get_kb_item("Host/cpu");
  if ( my_cpu != cpu ) 
  {
    if ( ! ( my_cpu =~ "i[3-6]86" && cpu == "i386" )  ) return 0;
  }
 }
 if ( release )
 {
  if ( "MDK" >< release && release != mdk_release ) return 0;
  if ( "SUSE" >< release && release != suse_release ) return 0;
  else if ( release == "RHEL4" && !egrep(pattern:"Red Hat Enterprise Linux.*release 4", string:rh_release) ) return 0;
  else if ( release == "RHEL3" && !egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:rh_release) ) return 0;
  else if ( release == "RHEL2.1" && !egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release) ) return 0;
  else if ( release == "FC1" && "Fedora Core release 1" >!< rh_release ) return 0;
  else if ( release == "FC2" && "Fedora Core release 2" >!< rh_release ) return 0;
  else if ( release == "FC3" && "Fedora Core release 3" >!< rh_release ) return 0;
  else if ( release == "FC4" && "Fedora Core release 4" >!< rh_release ) return 0;
  else if ( release == "FC5" && "Fedora Core release 5" >!< rh_release ) return 0;
  else if ( release == "CentOS-3" && "CentOS release 3" >!< centos_release ) return 0;
  else if ( release == "CentOS-4" && "CentOS release 4" >!< centos_release ) return 0;
 }
 else if ( ! egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release", string:rh_release) ) return 0;

 if ( "SUSE" >< release ) 
 	rpms = get_kb_item("Host/SuSE/rpm-list");
 else if ("MDK" >< release)
	rpms = get_kb_item("Host/Mandrake/rpm-list");
 else if ( "CentOS" >< release )
	rpms = get_kb_item("Host/CentOS/rpm-list");
 else
	rpms = get_kb_item("Host/RedHat/rpm-list");

 if ( ! rpms ) return 0;


 if ( prefix )
  {
  if ( "kernel-" == prefix )
      package = egrep(pattern:"^kernel-([0-9]|unsupported|source|smp|hugemem|doc|BOOT)", string:rpms);
    else 
      package = egrep(pattern:"^" + prefix, string:rpms);
  }
 else
 {
  my_rpm = parse_rpm_name(rpm:reference, yank:yank);
  package = egrep(pattern:"^" + my_rpm["name"] + "-[0-9]", string:rpms);
 }
  
 if ( ! package ) return 0;
 lines = split(package, sep:'\n', keep:0);
 foreach package (lines)
 {
	 e =  rpm_cmp(rpm:package, reference:reference, yank:yank, epoch:epoch);
	 if ( e < 0 )
		{
		 if ( "kernel-" >!< reference )
			return 1;
		}
		else ok = 1;
 }

 if ( "kernel-" >!< reference )
	return 0;
 else
	{
	if ( ok ) 
	 return 0;
	else 
         return 1;
	}
}


function rpm_exists(rpm, release)
{
 local_var rh_release,suse_release, mdk_release, rpms, package, lines, e, my_rpm, ok;

 rh_release = get_kb_item("Host/RedHat/release");
 suse_release = get_kb_item("Host/SuSE/release");
 mdk_release = get_kb_item("Host/Mandrake/release");

 if ( release )
 {
  if ( "MDK" >< release && release != mdk_release ) return 0;
  if ( "SUSE" >< release && release != suse_release) return 0;
  if ( release == "RHEL4" && !egrep(pattern:"Red Hat Enterprise Linux.*release 4", string:rh_release) ) return 0;
  if ( release == "RHEL3" && !egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:rh_release) ) return 0;
  if ( release == "RHEL2.1" && !egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release) ) return 0;
  if ( release == "FC1" && "Fedora Core release 1" >!< rh_release ) return 0;
  if ( release == "FC2" && "Fedora Core release 2" >!< rh_release ) return 0;
  if ( release == "FC3" && "Fedora Core release 3" >!< rh_release ) return 0;
  if ( release == "FC4" && "Fedora Core release 4" >!< rh_release ) return 0;
 }
 else if ( ! egrep(pattern:"(Red Hat.*(Enterprise|Advanced).*release|Fedora Core)", string:rh_release) ) return 0;

 if ( "SUSE" >< release ) 
 	rpms = get_kb_item("Host/SuSE/rpm-list");
 else if ("MDK" >< release)
	rpms = get_kb_item("Host/Mandrake/rpm-list");
 else
	rpms = get_kb_item("Host/RedHat/rpm-list");


 if ( ! rpms ) return 0;

 if ( egrep(pattern:"^" + rpm, string:rpms) ) 
	return 1;
  else
	return 0;

}

