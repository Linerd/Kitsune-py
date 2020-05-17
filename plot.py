#!/usr/bin/env python3.7

from matplotlib import pyplot as plt
from matplotlib import cm
import pickle
import numpy as np
import sys
from config import *
from scipy.stats import norm

#TODO: Change below for input result data
RESULT = 'kitsune_processed_pkts_blocking_55000'

print("Reading data")
with open('./results/%s.p' % RESULT, 'rb') as f:
    data = pickle.load(f)

data = np.array(data)
times = data[:, 0]
RMSEs = data[:, 1]
benignSample = np.log(RMSEs[FMgrace+ADgrace+1:])
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

plt.figure(figsize=(20, 10))
fig = plt.scatter(times[FMgrace+ADgrace+1:], RMSEs[FMgrace+ADgrace+1:],
                  s=2, c=logProbs[FMgrace+ADgrace+1:], cmap='RdYlGn')
plt.yscale("log")
plt.ylabel("RMSE (log scaled)", fontsize=28)
plt.yticks(fontsize=28)

plt.xlabel("Timestamp (s)", fontsize=28)
N = 3
selected_times = times[FMgrace+ADgrace+1:]
labels = np.array([0, 2500, 5000, 16400])
ticks = selected_times[0] + (labels * int(1e6))
plt.xticks(ticks, labels, fontsize=28)

figbar = plt.colorbar(pad=0.01)
figbar.ax.set_ylabel('Log Probability\n ', rotation=270, fontsize=28, labelpad=30)
figbar.ax.tick_params(labelsize=28)

# NOTE: uncomment below to generate annotations
# plt.annotate('Mirai C&C channel opened [Telnet]', xy=(times[121662], RMSEs[121662]), xytext=(
#     times[151662], 1), arrowprops=dict(facecolor='black', shrink=0.05), fontsize=28)
# plt.annotate('Mirai Bot Activated\nMirai scans network\nfor vulnerable devices', xy=(
#     times[122662], 1), xytext=(times[122662], 15), arrowprops=dict(facecolor='black', shrink=0.05), fontsize=28)
# plt.annotate('Mirai Bot launches\nDoS attack', xy=(times[370000], 100), xytext=(
#     times[390000], 1000), arrowprops=dict(facecolor='black', shrink=0.05), fontsize=28)

plt.savefig('./results/%s.pdf' % RESULT)
