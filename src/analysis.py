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

    aes_data = np.frombuffer(aes_data, dtype=np.uint8).reshape(size)
    caes_data = np.frombuffer(caes_data, dtype=np.uint8).reshape(size)

    # Calculate Corellation
    right_aes_corr = analyze_right(img, aes_data)
    right_caes_corr = analyze_right(img, caes_data)

    bottom_aes_corr = analyze_bottom(img, aes_data)
    bottom_caes_corr = analyze_bottom(img, caes_data)

    diagonal_aes_corr = analyze_diagonal(img, aes_data)
    diagonal_caes_corr = analyze_diagonal(img, caes_data)

    print(f"{file_name},{right_aes_corr},{right_caes_corr},{bottom_aes_corr},{
          bottom_caes_corr},{diagonal_aes_corr},{diagonal_caes_corr}")


def calculate_corr(data):
    x = [d[0] for d in data]
    y = [d[1] for d in data]
    return pearsonr(x, y).correlation


def analyze_right(original, data):
    left = []
    for i in range(original.shape[0]):
        for j in range(original.shape[1] - 1):
            left.append((data[i][j], data[i][j+1]))

    return calculate_corr(left)


def analyze_bottom(original, data):
    bottom = []
    for i in range(original.shape[0] - 1):
        for j in range(original.shape[1]):
            bottom.append((data[i][j], data[i+1][j]))

    return calculate_corr(bottom)


def analyze_diagonal(original, data):
    diagonal = []
    for i in range(original.shape[0] - 1):
        for j in range(original.shape[1] - 1):
            diagonal.append((data[i][j], data[i+1][j+1]))

    return calculate_corr(diagonal)


print("filename,right_aes_corr,right_caes_corr,bottom_aes_corr,bottom_caes_corr,diagonal_aes_corr,diagonal_caes_corr")
with mp.Pool(4) as pool:
    pool.map(analysis, images)
