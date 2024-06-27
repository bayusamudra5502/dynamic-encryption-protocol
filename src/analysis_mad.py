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


def analysis(image):
    file_name = image.split('/')[-1]

    # Read image
    img = np.array(Image.open(image).convert('L'))
    size = img.shape

    dimension_size = size[0] * size[1]

    aes_data = open(f"{OUTPUT_DIR_AES}/aes.{file_name}",
                    "rb").read()[:dimension_size]
    caes_data = open(f"{OUTPUT_DIR_CAES}/caes.{file_name}",
                     "rb").read()[:dimension_size]

    aes_data = np.frombuffer(aes_data, dtype=np.uint8)
    caes_data = np.frombuffer(caes_data, dtype=np.uint8)

    # Calculate MAD
    aes_mad = calculate_mad(aes_data)
    caes_mad = calculate_mad(caes_data)
    original_mad = calculate_mad(img)

    print(f"{file_name},{aes_mad},{caes_mad},{original_mad}")


def calculate_mad(data):
    result = np.array([0] * 256)

    for i in range(256):
        result[i] = np.sum(data == i)

    avg = np.mean(result)
    mad = np.mean(np.abs(result - avg))

    return mad


print("file,aes_mad,caes_mad,original_mad")
with mp.Pool(mp.cpu_count()) as pool:
    pool.map(analysis, images)
