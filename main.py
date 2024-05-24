import sys

from des import DesKey

def main(key=b"12345678"):
    key0 = DesKey(key)
    message = input()
    e = key0.encrypt(message=message.encode("utf-8"), padding=True)
    print("Encrypted: ", e)
    d = key0.decrypt(message=e, padding=True)
    print("Decrypted ", d.decode())
    

if len(sys.argv)>1:
    main(sys.argv[1])
else:
    main()