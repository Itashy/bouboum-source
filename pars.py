from packets.bytearray import ByteArray

p = '\x00\x10\x00\x00\x00\x06\x0e\x0b\x01\x01\x01\x01\x00\x01\x01\x00\x02\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x02\x00\x01\x00\x01\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x02\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x01\x00\x01\x01\x01\x02\x01\x00\x01\x00\x01\x00\x01\x01\x01\x01\x00\x01\x00\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x02\x01\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x01\x02\x01\x02\x00\x01\x00\x00\x01\x01\x01\x00\x01\x00\x01\x00\x00\x01\x01\x01\x02\x01\x00\x00\x00\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x00\x01\x01\x01\x01\x01\x00\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x00\x01\x00\x01\x00\x01\x00\x01\x01\x01\x01\x01\x02\x01\x01\x01\x00\x01\x01\x00\x01\x00\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x02\x02\x02\x01\x01\x02\x01\x00\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x02\x02\x02\x01\x01\x00\x00\x00\x01\x01\x01\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x02\x02\x02\x01\x01\x01\x00\x01\x01\x00\x00\x01\x00\x00\x02\x01\x01\x01\x01\x01\x00\x01\x00\x01\x01\x00\x01\x00\x00\x00\x00\x02\x01\x01\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x00\x01\x01\x00\x01\x01\x01\x02\x01\x01\x01\x01\x01\x00\x01\x01\x00\x00\x01\x00\x01\x00\x01\x01\x01\x00\x02\x01\x00\x01\x00\x00\x01\x01\x00\x01\x01\x00\x02\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x00\x02\x01\x01\x00\x01\x01\x00\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x02\x00\x00\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x00\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x00\x00\x01\x00\x00\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x02\x01\x01\x01\x01\x00\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x02\x01\x01\x00\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x00\x01\x01\x00\x01\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x02\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x00\x01\x00\x01\x01\x00\x02\x01\x01\x00\x01\x01\x01\x00\x00'
p='\x00\x17\x00\x00\x00\x07\x17\x05\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x00\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x02\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x00\x02\x02\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x01\x01\x00\x01\x02\x01\x02\x00\x01\x01\x01\x01\x00\x00\x01\x01\x01\x00\x00\x01\x00\x02\x01\x01\x02\x01\x01\x01\x01\x01\x00\x01\x00\x00\x01\x00\x01\x00\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x00\x01\x01\x01\x00\x00\x00\x01\x01\x01\x00\x00\x01\x01\x00\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x00\x01\x01\x02\x00\x01\x00\x01\x01\x00\x00\x01\x01\x00\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x01\x01\x02\x02\x02\x02\x01\x00\x00\x01\x01\x01\x01\x01\x00\x00\x02\x02\x02\x02\x01\x01\x01\x00\x00\x00\x00\x01\x01\x00\x01\x00\x02\x02\x01\x01\x01\x01\x01\x01\x00\x00\x00\x01\x01\x00\x00\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x00\x01\x01\x01\x00\x01\x00\x01\x01\x01\x02\x00\x01\x00\x01\x01\x01\x00\x01\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x00\x00\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x00\x01\x00\x00\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x00\x01\x01\x01\x00\x01\x00\x00\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x00\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x00\x01\x00\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x02\x02\x01\x01\x01\x00\x01\x01\x01\x00\x00\x01\x01\x00\x02\x02\x02\x02\x01\x01\x00\x01\x01\x00\x01\x00\x01\x00\x02\x02\x02\x02\x00\x00\x01\x01\x02\x00\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x00\x00\x01\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x01\x00\x02\x01\x00\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x00\x02\x01\x02\x01\x01\x01\x01\x00\x00\x00\x00\x01\x01\x00\x00\x01\x01\x01\x01\x02\x02\x01\x00\x00\x00\x01\x00\x00\x00\x01\x01\x01\x01\x00\x00\x01\x01\x01\x02\x00\x01\x00\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x00\x01\x00\x01\x02\x01\x00\x00\x01\x00\x01\x01\x00\x01\x00\x00\x01\x00\x00\x01\x00\x00\x02\x01\x01\x01\x01\x00\x01\x01\x00\x01'

p = ByteArray(p)

print p.readShort()

print p.readInt()

print p.readByte()
print p.readByte()

print 'len', '-', len(p.toString())
while len(p.toString()) > 0:
	p.readByte()

p = '\x00\x01\x00\tDevsaidero\xda\x00\x00\x00\x04\x04\xe2\x19\x00'
p = ByteArray(p)

playersLen = p.readShort()

playersReaded = 0

while playersReaded < playersLen:
	print p.readUTF()
	print p.readShort()
	print p.readBoolean()
	print p.readByte()
	print p.readShort()
	print p.readShort()
	print p.readByte()
	print p.readByte()
	playersReaded += 1

print '\n-------\n'
p = '\x14\x8c\t\x11\x08\x11\t\x10'
p = ByteArray(p)

print p.readShort()

print p.readByte()
print p.readByte()
print p.readByte()
print p.readByte()
print p.readByte()
print p.readByte()

p = '00 00 00 2D 66 46 00 00 00 00 00 16 00 00 00 11 00 32 03 00 64 04 00 C8 06 01 90 13 01 F4 02 03 20 07 03 E8 09 03 E8 08 05 DC 05 07 D0 '.replace(' ','').decode('hex') #'00 00 00 2D 66 46 00 00 00 34 11 16 00 00 00 11 00 00 03 00 64 04 00 C8 06 01 90 13 01 F4 02 03 20 07 03 E8 09 03 E8 08 05 DC 05 07 D0 '.replace(' ','').decode('hex')
p = ByteArray(p)

print '\n-------\n'

p.readInt()
p.readShort()

"""
this.var_1570 = param1.readInt();
            this.var_506 = param1.readByte();
            var _loc_2:* = param1.readByte();
            this.var_841 = new Vector.<int>(_loc_2, true);
            var _loc_3:* = class_100.const_1;
            while (_loc_3 < _loc_2)
            {
                
                this.var_841[_loc_3] = param1.readByte();
                this.var_841[_loc_3 + class_100.const_2] = param1.readShort();
                _loc_3 = _loc_3 + class_100.const_3;
            }
            return;
            """
var_1570 = p.readInt()
var_506 = p.readByte()
loc_2 = p.readByte()
var_841 = [0]*loc_2
loc_3 = 0
while loc_3 < loc_2:
	var_841[loc_3] = p.readByte()
	var_841[loc_3 + 1] = p.readShort()
	loc_3 = loc_3 + 2

print var_841, var_506, loc_2




