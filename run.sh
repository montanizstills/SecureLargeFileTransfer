#!/bin/sh


#A generates a pair of public and private keys with names: [A’s full
#name]-public-key, [A’s full name]-private-key

openssl genrsa -out ./csci6746/montanizstills-private-key.pem 2048

#A makes a certificate request. The certificate request file name: [A’s
#full name].csr. A sends the file to C for a certificate.

openssl req -new -key ./csci6746/montanizstills-private-key.pem -out ./csci6746/montanizstills.csr

#C issues two certificates to A, and A needs to verify which one is valid
#through checking C’s own certificate; A shares the valid certificate with B (so that B can obtain A’s public key
#and other info from A’s certificate later)
# compare A1 and A2 with C’s certificate

openssl verify -verbose -CAfile ./csci6746/True-CA.crt ./csci6746/montanizstills-1.crt
openssl verify -verbose -CAfile ./csci6746/True-CA.crt ./csci6746/montanizstills-2.crt

#A receives B’s certificate and uses Wireshark to capture the certificate
#sharing process; A finds out the identity/public key info of B in the Wireshark
#environment

#<Wireshark>###############################################

#7. (5 pts) A needs to transfer a large secret file ([YourFullName].txt) to B via
#netcat. Use the following steps to change the sending file:
  #a. Download and modify the attached file to contain A’s full name at the very
  #beginning of the file: This is to confirm that this file comes from A (A’s full name) .

  #b. The file name should be changed to: [A’s full name].txt (Full name should not
  #contain any space between first, middle and last names).

# receiver
nc -l -p port > montanizstills.txt

# sender
nc dst port < montanizstills.txt

echo "Benard" > .tmp
cat montanizstills.txt >> .tmp
mv .tmp montanizstills.txt


#8. (5 pts) A uses AES algorithm (cbc mode) and a key(password) to encrypt
#the file([A’s full name].txt) and sends it to B. A’s encrypted file name: [A’s full
#name].cipher

openssl enc -aes-256-cbc -in montanizstills.txt -out output.txt -k yourpassword

#9. (5 pts) A stores the symmetric key in a file called: [A’s full name]-key.txt

openssl rand -base64 32 > montanizstills-key.txt

#10. (5 pts) A uses B’s public key( or certificate) to encrypt the symmetric key
#file ([A’s full name]-key.txt), and sends the encrypted file to B. The encrypted
#key file name: [A’s full name]-key.cipher

openssl pkeyutl -encrypt -certin -inkey cert-B.pem -in montanizstills-key.txt -out montanizstills-key.cipher

#11. (5 pts) A signs the hash value of the large secret file ([A’s full name].txt)
#and sends the signed hash value to B via netcat. The signed file name is [A’s
#full name].txt.sgn.

openssl dgst -sha256 -sign montanizstills-private-key.pem -out montanizstills.txt.sgn montanizstills.txt
nc dst port < montanizstills.txt.sgn

#12. (5 pts) A starts Wireshark to capture the process to receive B’s encrypted
#key file. A identifies the content of the encrypted key file in Wireshark
#environment.

#<Wireshark>###############################################

#13. A uses private key to decrypt [B’s full name]-key.cipher to obtain the key:
#[B’s full name]-key.txt

openssl pkeyutl -decrypt -in B-key.cipher -inkey montanizstills-private-key.pem -out montanizstills-key.txt

#14. (5 pts) A receives B’s encrypted large file, and uses the key in [B’s full
#name]-key.txt to decrypt the file: [B’s full name].cipher into [B’s full
#name].txt , and shows the content: This is to confirm that this file comes
#from B (full name)

nc -l src_port > B.cipher
openssl decrypt 3des -in B.cipher -out B.txt -pass file:montanizstills-key.txt
cat B.txt

#15. (5 pts) A receives B’s the digital signature. A verifies that the file sent was
#signed by B and was not changed over the transmission.
#"""
openssl dgst -sha256 -verify B-public-key.pem -signature B.txt.sgn B.txt