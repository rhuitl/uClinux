setMode -bscan
setCable -p lpt1
addDevice -p 1 -file etc/xc18v04_vq44.bsd
assignfile -p 1 -file  etc/xc18v04_vq44.bsd
addDevice -p 2 -file implementation/download.bit
addDevice -p 3 -file etc/xcr3064xl_vq44.bsd
assignfile -p 3 -file  etc/xcr3064xl_vq44.bsd
program -p 2
quit
