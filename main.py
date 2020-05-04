#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  import time
import copy
import pickle
import os
from pprint import pprint
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import math
from gen_data import get_all


# Fetch Data
def load_data(file):
    with open(file, 'rb') as f:
        data_list = pickle.load(f)
    return data_list


dump_path = os.path.join(os.path.dirname(__file__), 'pickle')

print(dump_path)

dump_file_list = list(
    map(lambda x: os.path.join(dump_path, x), os.listdir(dump_path)))

data_set = []

for i in dump_file_list:
    data_set += load_data(i)

pprint(data_set)

x_data = []
y_data = []

for x, y in data_set:
    x_data.append([x[3], x[0], x[2]])
    y_data.append([y])

x_data = np.asarray(x_data, dtype=np.float32)
y_data = np.asarray(y_data, dtype=np.float32)
data_set_fixed = []
for x in data_set:
    data_set_fixed.append([[x[0][0] * 6.5, x[0][1] * 15, x[0][2], x[0][3]],
                           x[1], x[0][5]])

# KNN and Test

KNN_k = 5
target_file = '/home/v1me/proj/graduation_thesis/project/test/samples/sample_group_7/libaudit_O1.so'


def distance(a, b):
    sum = 0
    for n1, n2 in zip(a, b):
        sum += (n1 - n2) * (n1 - n2)
    return math.sqrt(sum)


def fix_dataset(node):
    d_set = copy.deepcopy(data_set_fixed)
    for i in d_set:
        i.append(distance(i[0], node))
    d_set.sort(key=lambda x: x[3])
    return d_set


def result(data_set):
    cnt0 = 0
    cnt1 = 0
    cnt2 = 0
    for i in range(KNN_k):
        if data_set[i][1] == 0:
            cnt0 += 1
        elif data_set[i][1] == 1:
            cnt1 += 1
        else:
            cnt2 += 1
    max_ = max(cnt0, cnt1, cnt2)
    if max_ == cnt0:
        return 0
    elif max_ == cnt1:
        return 1
    else:
        return 2


node = get_all(target_file)[0:4]
print('result: O' + str(result(fix_dataset(node))))

#  cnt = 0
#  cnt_ = 0
#  for i in data_set_fixed:
#      if result(fix_dataset(i[0])) == i[1]:
#          cnt += 1
#      cnt_ += 1
#  print(cnt / cnt_)
#  print(cnt, cnt_)

#  ax = plt.subplot(111, projection='3d')
#  ax.view_init(elev=0, azim=0)
#  #  ax.view_init()
#  for node, val in zip(x_data, y_data):
#      if val == 0:
#          color = 'y'
#      elif val == 1:
#          color = 'r'
#      else:
#          color = 'b'
#      ax.scatter(*node, c=color)
#  ax.set_zlabel('W')
#  ax.set_ylabel('Y')
#  ax.set_xlabel('X')
#  plt.savefig("mygraph.png")
