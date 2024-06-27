from PIL import Image
import os
import numpy as np
import seaborn as sns
from lib.crypto.csprng import *
from lib.util import *
from lib.crypto.aes import *
from random import random
import matplotlib.pyplot as plt
from scipy.stats import *
import multiprocessing as mp

OUTPUT_DIR_AES = "../server/aes"
OUTPUT_DIR_CAES = "../server/caes"
images = ["../server/img/1.jpg", "../server/img/2.jpg",
          "../server/img/3.jpg", "../server/img/4.jpg",
          "../server/img/5.jpg", "../server/img/6.jpg",
          "../server/img/7.jpg", "../server/img/8.jpg",
          "../server/img/9.jpg", "../server/img/10.jpg"
          ]


def encrypt_images(image):
    file_name = image.split('/')[-1]
    print(f"Encrypting {file_name}")

    # Read image
    img = Image.open(image).convert('L')
    original = np.array(img)
    data_bytes = original.tobytes()

    # Encrypt image with AES
    aes_key = os.urandom(16)

    aes_enc = AES.new(aes_key, AES.MODE_CTR, nonce=os.urandom(12))
    enc_aes_data = aes_enc.encrypt(pad(data_bytes, 16))

    # Save encrypted image
    open(f"{OUTPUT_DIR_AES}/aes.{file_name}", "wb").write(enc_aes_data)
    print(f"Encrypted AES image saved at {OUTPUT_DIR_AES}/aes.{file_name}")

    # Encrypt with Dynamic AES
    chaos = SineHenonMap(random(), random(), random())
    iv = SineHenonMap(random(), random(), random())

    aes = DynamicAES(chaos, iv)
    enc_caes_data = aes.encrypt(data_bytes)

    # Save encrypted image
    open(f"{OUTPUT_DIR_CAES}/caes.{file_name}", "wb").write(enc_caes_data)
    print(f"Encrypted CAES image saved at {OUTPUT_DIR_CAES}/caes.{file_name}")


with mp.Pool(mp.cpu_count()) as pool:
    pool.map(encrypt_images, images)
