from chaos import *
from util import *
from aes import *

import argparse

chaos = HenonMap(1.00, 2.00, 3.00)
iv = b'abcdefghijklmnop'

def encrypt(file_path: str, output_path: str, auth = True):
  if auth:
    daes = DynamicAESWithHMAC(chaos, iv=iv, rotate_size=128)
  else:
    daes = DynamicAES(chaos, iv=iv, rotate_size=128)

  with open(file_path, 'rb') as f:
    result = daes.encrypt(f.read())

  with open(output_path, 'wb') as f:
    f.write(result)

def decrypt(file_path: str, output_path: str, auth = True):
  if auth:
    daes = DynamicAESWithHMAC(chaos, iv=iv, rotate_size=128)
  else:
    daes = DynamicAES(chaos, iv=iv, rotate_size=128)
  
  with open(file_path, 'rb') as f:
    result = daes.decrypt(f.read())

  with open(output_path, 'wb') as f:
    f.write(result)

parser = argparse.ArgumentParser(
              prog='main.py',
              description='This is the dynamic encryptor')
parser.add_argument('--mode' , '-m', help="Application mode (encrypt or decrypt)")
parser.add_argument('filename', help="Input filename")
parser.add_argument('--output' ,'-o', help="Output filename")
parser.add_argument('--no-auth' ,'-a', help="Without Auth", action=argparse.BooleanOptionalAction, type=bool, default=False)

args = vars(parser.parse_args())
print(args)
fname = args['filename']
oname = args['output']
noauth = args['no_auth']

if args['mode'] == 'encrypt':
  encrypt(fname, oname, auth= not noauth)
elif args['mode'] == 'decrypt':
  decrypt(fname, oname, auth= not noauth)
else:
  raise Exception("Unknown type :(")
