# Ben Myers <0003571400@mcimail.com>

# Sum up sizes of OBJ files in current directory
# A clumsy script to count OBJs and sum up their sizes
# run with 
#       bmawk -fobjsize.awk workfile
# or similar command syntax with your awk program
# where workfile is a work file
BEGIN {
# redirection done by shelled command
system("dir *.obj >" ARGV[1])
osize = 0   # size accumulator
ocount = 0  # obj counter
}
# Now read workfile back, skipping lines that are not files
$2 == "OBJ" { osize += $3 ; ocount++ }
END {
print ocount " OBJs, total size " osize " bytes"
system("del "ARGV[1])
}
