import sys

from src.security import des

if len(sys.argv)>1:
    des.main(sys.argv[1])
else:
    des.main()