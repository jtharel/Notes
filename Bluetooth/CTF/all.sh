#Flag 1
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "12345678901234567890"|xxd -ps)

#Flag 2
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "d205303e099ceff44835"|xxd -ps)

#Flag 3 - only submit the first 20 characters of the md5sum
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "5cd56d74049ae40f442e"|xxd -ps)

#Flag 4
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "2b00042f7481c7b056c4"|xxd -ps)

#Flag 5
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "3873c0270763568cf7aa"|xxd -ps)

#Flag 6
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "c55c6314b3db0a6128af"|xxd -ps)

#Flag 7
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "1179080b29f8da16ad66"|xxd -ps)

#Flag 8
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "f8b136d937fad6a2be9f"|xxd -ps)

#Flag 9
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "933c1fcfa8ed52d2ec05"|xxd -ps)

#Flag 10
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "6ffcd214ffebdc0d069e"|xxd -ps)

#Flag 11
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "5ec3772bcd00cf06d8eb"|xxd -ps)

#Flag 12
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "c7b86dd121848c77c113"|xxd -ps)

#Flag 13
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "c9457de5fd8cafe349fd"|xxd -ps)

#Flag 14
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "b6f3a47f207d38e16ffa"|xxd -ps)

#Flag 15
#sudo ./bdaddr -i hci0 -r 11:22:33:44:55:66
#sudo bleah -b 24:0A:C4:08:D7:26 -n 0x002c -d "aca16920583e42bdcf5f"


#Flag 16
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "b1e409e5a4eaf9fe5158"|xxd -ps)

#Flag 17
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "d41d8cd98f00b204e980"|xxd -ps)

#Flag 18
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "fc920c68b6006169477b"|xxd -ps)

#Flag 19
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "fbb966958f07e4a0cc48"|xxd -ps)

#Flag 20
gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x002c -n $(echo -n "d953bfb9846acc2e15ee"|xxd -ps)

