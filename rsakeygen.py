import base64
import binascii

N=""
E=""
P=""
Q=""
D=""
E1=""
E2=""
E3=""


def makePEM(rawData):
    out="-----BEGIN RSA PRIVATE KEY-----"
    out+="\n"
    encoded=base64.b64encode(rawData)
    nThunks=len(encoded)/64
    nRest=len(encoded)%64
    for k in range(0, nThunks):
        out+=encoded[k*64:(k+1)*64]
        out+="\n"
    out+=encoded[nThunks*64:nThunks*64+nRest]
    out+="\n-----END RSA PRIVATE KEY-----"
    return out


#ASN.1 stuff:
def encodeINTEGER(intstr):
    input_len=len(intstr)/2
    encode=""
    if (input_len<=127):
        encode+="\x02"+chr(input_len)
        encode+=intstr.decode("hex")
        return encode
    if (input_len/2<=255):
        encode+="\x02"+chr(0x81)+chr(input_len)
        encode+=intstr.decode("hex")
        return encode
    ln1=(input_len&0xFF00)>>8
    ln2=input_len&0xFF
    encode+="\x02"+chr(0x82)+chr(ln1)+chr(ln2)
    return encode

def encodeSEQUENCE(buff):
    out="\x30"
    ln1=(len(buff)&0xFF00)>>8
    ln2=len(buff)&0xFF
    out+=chr(0x82)+chr(ln1)+chr(ln2)
    out+=buff
    return out


print "---- RSA PEM FILE GEN TOOL ----"
print "moduli.txt - N=P.Q"
print "E.txt - public exponent"
print "P.txt - factor #1"
print "Q.txt - factor #2"
print "D.txt - E^-1 over EulerPhi(N)"
print "E1.txt - d mod (p-1)"
print "E2.txt - d mod (q-1)"
print "E3.txt - q^-1 mod p"

print "If any of these values are missing, a dummy value is inserted, tipically for RSA-1024"

#reading N
try:
    hMod=open("moduli.txt", "r")
    N=hMod.read()
    hMod.close()
except IOError:
    print "could not open moduli.txt...assuming a random, dummy (1024-bit) value"
    N="00cf7411b092a8b1c15ba727bcdffe4dcc9602f54c24620284682fa7e415aaecc4549dde1a8ec113d0f3bfd9ec85e7351157c87afae96abb6bef3476d27b52bf77213ce4a6e07eeb815a0753fb7cee2ceff065c964b85fd06d9b837432051f500df0307e16ae4f4fe058792e010d4479ebeda7f024fb2c746be6adb939811d42e1"

#reading E
try:
    hE=open("E.txt", "r")
    E=hE.read()
    hE.close()
except IOError:
    print "E.txt was not found...assuming 0x010001"
    E="010001"

#reading P
try:
    hP=open("P.txt", "r")
    P=hP.read()
    hP.close()
except IOError:
    print "No P.txt factor found ... assuming random, dummy (512-bit) value"
    P="00fc8eecd564d62d5a24e95c1d5a5f1eacc946804a35f9864be7791f8fc9d41165d45b94c5431020dc7df49151e1b4535cd7310d2d99eb9c34a6bad32526cba2bd"
    print "Checks out..." + str(len(P)/2*8) + " bits."

#reading Q
try:
    hQ=open("Q.txt", "r")
    Q=hQ.read()
    hQ.close()
except IOError:
    print "No Q.txt factor found ... assuming random, dummy (512-bit) value"
    Q="00d247ca7ec42c418bb4fcdbb1f3821e0acf6e4cb1c0834938804c588a79b0069f7f3d8c9575d137ef800a8381bf31c9a158cf3bb0549d9b1462e4a0c535aed4f5"
    print "Checks out..." + str(len(Q)/2*8) + " bits."

#reading D
try:
    hD=open("D.txt", "r")
    D=hD.read()
    hD.close()
except IOError:
    print "No D.txt factor found ... assuming random, dummy (proper-bit) value"
    D="3cd8984fa7d45ebe8db94b4874924c1353746ea9f489e29f1f47cb0074f27b1b628e2314bb061a5fd0fe5656af378f331502323fe1b2726247f8a5593ade9c5536e3cd2b53b1e9825a645bb501dfd39d52eb103d5190d9358cfd8e3111920b2f4b6e81be874fc7866abb212357839dd2052c653dcb911d5f5a62d32551638621"
    print "Checks out..." + str(len(D)/2*8) + " bits."

#reading E1 = d mod (p-1)
try:
    hE1=open("E1.txt", "r")
    E1=hE1.read()
    hE1.close()
except IOError:
    print "No E1.txt factor found ... assuming random, dummy (proper-bit) value"
    E1="008a1aa9bd42e7af6314be1ae5de2e177b0a9127c3ece1e6a3090f7dc7c5e8d61ea5d1f2772fe5d8e25969ec312747d131fa66533b75689641604ed6f900cee7cd"
    print "Checks out..." + str(len(D)/2*8) + " bits."

#reading E2 = d mod (q-1)
try:
    hE2=open("E2.txt", "r")
    E2=hE2.read()
    hE2.close()
except IOError:
    print "No E2.txt factor found ... assuming random, dummy (proper-bit) value"
    E2="0f893252cf579db81eb517de3be97f22b954a2e1f7213c05aaa4f95db1c3e9995b234701bbe4ab474ca47a36d9d369dc3bdd83c1715efb9833fe444a8dbecf09"
    print "Checks out..." + str(len(D)/2*8) + " bits."

#reading E3 = q^-1 mod p
try:
    hE3=open("E3.txt", "r")
    E3=hE3.read()
    hE3.close()
except IOError:
    print "No E3.txt factor found ... assuming random, dummy (proper-bit) value"
    E3="00f429562307f7b634d7edd50357df7ef8800afd53235521310968848fffb19f42db91f3e80ea7d9750730d9ea8c25ce742651f4e2f3dee74f1caac234cf683048"
    print "Checks out..." + str(len(D)/2*8) + " bits."



print "\nStarting encoding of PEM RSA key"

BUFF=""
BUFF+=encodeINTEGER("00") #this seems to appear in many contexts
BUFF+=encodeINTEGER(N) #N
BUFF+=encodeINTEGER(E) #E
BUFF+=encodeINTEGER(D) #D
BUFF+=encodeINTEGER(P) #P
BUFF+=encodeINTEGER(Q) #Q
BUFF+=encodeINTEGER(E1) # d mod p-1
BUFF+=encodeINTEGER(E2) # d mod q-1
BUFF+=encodeINTEGER(E3) # q^-1 mod p
print "\n" + makePEM(encodeSEQUENCE(BUFF))
print "\n" + binascii.hexlify(encodeSEQUENCE(BUFF))
