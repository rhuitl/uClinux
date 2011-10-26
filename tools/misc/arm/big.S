
.text

setbig:
        mrc     p15, 0, r0, c1, c0, 0
        orr     r0, r0, #0x80
        mcr     p15, 0, r0, c1, c0, 0

        mrc  p15,0,r0,c2,c0,0
        mov  r0,r0
        sub  pc,pc,#4


