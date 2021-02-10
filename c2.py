import numpy as np
from math import log,floor


#Nibble substitution table:
NibbleSub = np.array([0b1110, 0b0100, 0b1101, 0b0001, 0b0010, 0b1111, 0b1011, 0b1000, 0b0011, 0b1010, 0b0110, 0b1100, 0b0101, 0b1001, 0b0000, 0b0111])
#Inverse Nibble substitution table:
InverseNibbleSub = np.array([0b1110, 0b0011, 0b0100, 0b1000, 0b0001, 0b1100, 0b1010, 0b1111, 0b0111, 0b1101, 0b1001, 0b0110, 0b1011, 0b0010, 0b0000, 0b0101])

def Word16Sub(word):
    sub = np.empty([4],np.int8) 
    sub[0] = NibbleSub[word[0]]
    sub[1] = NibbleSub[word[1]]
    sub[2] = NibbleSub[word[2]]
    sub[3] = NibbleSub[word[3]]
    return sub

def InverseWord16Sub(word):
    sub = np.empty([4],np.int8) 
    sub[0] = InverseNibbleSub[word[0]]
    sub[1] = InverseNibbleSub[word[1]]
    sub[2] = InverseNibbleSub[word[2]]
    sub[3] = InverseNibbleSub[word[3]]
    return sub

def round_keys_generator(key):
    #Key 0
    K0 = np.empty([4],np.int8) 
    K0 = key
    
    #Key 1
    K1 = np.empty([4],np.int8)
    K1[0] = K0[0] ^ NibbleSub[K0[3]] ^ 0b0001
    K1[1] = K0[1] ^ K1[0]
    K1[2] = K0[2] ^ K1[1]
    K1[3] = K0[3] ^ K1[2]

    #Key 2
    K2 = np.empty([4],np.int8)
    K2[0] = K1[0] ^ NibbleSub[K1[3]] ^ 0b0010
    K2[1] = K1[1] ^ K2[0]
    K2[2] = K1[2] ^ K2[1]
    K2[3] = K1[3] ^ K2[2]

    return [K0, K1, K2]

def int_to_list(int):
    n_array = np.zeros(4, np.int8)
    for i in range(4):
        if(int&(2**i)):
            n_array[i] = 1
    return n_array

def galois_multiply(n, m):
    m = int_to_list(m)
    n = int_to_list(n)
    
    o = np.zeros([7], np.int8) #Maximum polynomial order when multiplying two polynomials of order 3 is 6

    generator = "10011"
    generator = int(generator, 2)

    for i in range(4):
        for j in range(4):
            if(n[i] & m[j]):
                o[i+j] += 1
    for i in range(7):
        if((o[i] % 2 )== 0):
            o[i] = 0
        elif((o[i] % 2) == 1):
            o[i] = 1
    dividend = 0
    for i in range(len(o)):
        if(o[i] == 1):
            dividend += 2**i
    
    rem = dividend
    while(rem>=(1<<4)):
        
        shift = floor(log(rem, 2))
        
        if(shift >= 4):
            rem = rem ^ (generator << (shift-4))

    return rem

def ShiftRow(word):
    #Maybe parameterise this
    shift = np.empty([4],np.int8) 
    shift[0] = word[0]
    shift[1] = word[3]
    shift[2] = word[2]
    shift[3] = word[1]
    return shift

def MixColumn(word):
    d = np.array([[0b0011, 0b0010], [0b0010, 0b0011]])
    c = np.array([[word[0], word[2]], [word[1], word[3]]])
    mix = np.zeros(4,np.int8)
    mix[0] = galois_multiply(d[0,0],c[0,0]) ^ galois_multiply(d[0,1],c[1,0])
    mix[1] = galois_multiply(d[1,0],c[0,0]) ^ galois_multiply(d[1,1],c[1,0])
    mix[2] = galois_multiply(d[0,0],c[0,1]) ^ galois_multiply(d[0,1],c[1,1])
    mix[3] = galois_multiply(d[1,0],c[0,1]) ^ galois_multiply(d[1,1],c[1,1])

    #print(mix)
    return mix

#Input plaintext: 1001 1100 0110 0011
P = np.array([11, 13, 8, 1])

#Secret key: 1100 0011 1111 0000
K = np.array([0b1100, 0b0011, 0b1111, 0b0000]) 

#Calculate round keys
round_key = np.empty([4],np.int8)
round_key = round_keys_generator(K)

##################################
#Begin encryption process
##################################

print("Plaintext: ", P)
#First key addition
A = P ^ round_key[0]
#print(np.resize(A,(1,4)))
print("A: ", A)
#NibbleSub operation
B = Word16Sub(A)
print("B: ", B)
#ShiftRow operation
C = ShiftRow(B)
print("C: ", C)
#MixColumn operation
D = MixColumn(C)
print("D: ", D)
#Second Key addition
E = D ^ round_key[1]
print("E: ", E)
#Round 2 NibbleSub
F = Word16Sub(E)
print("F: ", F)
#Round 2 ShiftRow
G = ShiftRow(F)
print("G: ", G)
#Third Key addition
H = G ^ round_key[2]

print("Cyphertext: ", H)


##################################
#Begin decryption process
##################################

#Inverse Third Key addition
G_hat = H ^ round_key[2]
print("G_hat: ", G_hat)
#Inverse ShiftRow
F_hat = ShiftRow(G_hat)
print("F_hat: ", F_hat)
#Inverse NibbleSub
E_hat = InverseWord16Sub(F_hat)
print("E_hat: ", E_hat)
#Inverse Second Key addition
D_hat = E_hat ^ round_key[1]
print("D_hat: ", D_hat)
#Inverse MixColumn
C_hat = MixColumn(D_hat)
print("C_hat: ", C_hat)
#Inverse Shiftrow
B_hat = ShiftRow(C_hat)
print("B_hat: ", B_hat)
#Inverse NibbleSub
A_hat = InverseWord16Sub(B_hat)
print("A_hat: ", A_hat)
#Inverse First Key addition
P_hat = A_hat  ^ round_key[0]

print("Decrypted plaintext: ", P_hat)


