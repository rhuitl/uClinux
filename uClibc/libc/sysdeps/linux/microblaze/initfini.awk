#! /usr/bin/awk -f
# Contributed by Christian MICHON <christian_michon@yahoo.fr> to
#   eliminate the compile time dependancy on perl introduced by 
#   Erik's older initfini.pl 
# vim:ai:sw=2:

BEGIN \
{ alignval="";
  endp=0;
  end=0;
  system("touch crt[in].S");
  system("/bin/rm -f crt[in].S");
  omitcrti=0;
  omitcrtn=0;
  glb_idx = 0;
  while(getline < "initfini.S")
  { if(/\.endp/) {endp=1}
    if(/\.end/) {end=1}
    if(/\.align/) {alignval=$2}
# here comes some special stuff for the SuperH targets
#  We search for all labels, which uses the _GLOBAL_OFFSET_TABLE_
#  or a call_gmon_start function reference, and store
#  them in the glb_label array.
    if(/_init_EPILOG_BEGINS/) {glb_idx=1;glb_idx_arr[glb_idx]=0}
    if(/_fini_EPILOG_BEGINS/) {glb_idx=2;glb_idx_arr[glb_idx]=0}
    if(/EPILOG_ENDS/)         {glb_idx=0}
    if(/_GLOBAL_OFFSET_TABLE_/||/call_gmon_start/) {
      glb_label[glb_idx,glb_idx_arr[glb_idx]] = last;
      glb_idx_arr[glb_idx] += 1;
      glb_label[glb_idx,glb_idx_arr[glb_idx]] = $0;
      glb_idx_arr[glb_idx] += 1;
    }
    last = $1;
  }
  close("initfini.S");
}
# special rules for the SuperH targets (They do nothing on other targets)
/SH_GLB_BEGINS/ && glb_idx_arr[1]==0 && glb_idx_arr[2]==0 {omitcrti +=1}
/_init_SH_GLB/  {glb_idx=1}
/_fini_SH_GLB/  {glb_idx=2}
/SH_GLB_ENDS/ {omitcrti -=1}
/SH_GLB/ \
{
  if (glb_idx>0)
    {
      for (i=0;i<glb_idx_arr[glb_idx];i+=1) {
	print glb_label[glb_idx,i] >> "crti.S";
      }
      glb_idx = 0;
    }
  next;
}
# special rules for H8/300 (sorry quick hack)
/.h8300h/ {end=0}

# rules for all targets
/HEADER_ENDS/{omitcrti=1;omitcrtn=1;getline}
/PROLOG_BEGINS/{omitcrti=0;omitcrtn=0;getline}
/i_am_not_a_leaf/{getline}
/_init:/||/_fini:/{omitcrtn=1}
/PROLOG_PAUSES/{omitcrti=1;getline}
/PROLOG_UNPAUSES/{omitcrti=0;getline}
/PROLOG_ENDS/{omitcrti=1;getline}
/EPILOG_BEGINS/{omitcrtn=0;getline}
/EPILOG_ENDS/{omitcrtn=1;getline}
/TRAILER_BEGINS/{omitcrti=0;omitcrtn=0;getline}
/GMON_STUFF_BEGINS/{omitcrtn=1;getline}
/GMON_STUFF_PAUSES/{omitcrtn=0;getline}
/GMON_STUFF_UNPAUSES/{omitcrtn=1;getline}
/GMON_STUFF_ENDS/{omitcrtn=0;getline}

/_GLOBAL_OFFSET_TABLE_/||/gmon_start/ \
{
  if(omitcrti==0) {print >> "crti.S";}
  next;  # no gmon_start or GLOBAL_OFFSET_TABLE references in crtn.S
}

/END_INIT/ \
{ if(endp)
  { gsub("END_INIT",".endp _init",$0)
  }
  else
  { if(end)
    { gsub("END_INIT",".end _init",$0)
    }
    else
    { gsub("END_INIT","",$0)
    }
  }
}

/END_FINI/ \
{ if(endp)
  { gsub("END_FINI",".endp _fini",$0)
  }
  else
  { if(end)
    { gsub("END_FINI",".end _fini",$0)
    }
    else
    { gsub("END_FINI","",$0)
    }
  }
}

/ALIGN/ \
{ if(alignval!="")
  { gsub("ALIGN",sprintf(".align %s",alignval),$0)
  }
  else
  { gsub("ALIGN","",$0)
  }
}

omitcrti==0 {print >> "crti.S"}
omitcrtn==0 {print >> "crtn.S"}

END \
{ close("crti.S");
  close("crtn.S");
}
