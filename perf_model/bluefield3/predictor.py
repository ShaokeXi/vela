import os
import json
import numpy as np
from tqdm import tqdm
from math import log2, pow
from ast import literal_eval
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit

FIG_DIR = '/mnt/data/repo/vela/benchmark/figures'
LOG_DIR = '/mnt/data/repo/vela/benchmark/log'
MODEL = '/mnt/data/repo/vela/benchmark/model.json'

def rf_func(x, a, b, c):
    return x/(a+c*np.exp(-b/x)*x)


def roofline_model(data, figname = None):
    rate = {}
    for n in data:
        rate[int(n)] = float(data[n])*int(n)
    x = list(rate.keys())
    y = list(rate.values())
    try:
        popt, pcov = curve_fit(rf_func, x[1:], y[1:], bounds=(0, np.inf))
        pred = rf_func(x[1:], *popt)
        # np.insert(pred, 0, 0)
        # plt.figure()
        # plt.scatter(x, y)
        # plt.plot(x, pred, 'g--',
        #         label='fit: a=%5.3f, b=%5.3f, c=%5.3f' % tuple(popt))
        # plt.legend()
        # plt.savefig("{}/{}.png".format("new_rf_figures3", figname))
        y = y[1:]
        distance = [abs(y[i]-pred[i])/y[i] for i in range(len(y))]
        # return (figname, "%.3f" % np.mean(distance), "%.3f" % np.median(distance), "%.3f" % np.max(distance))
        # return (figname, "%.3f" % popt[0], "%.3f" % popt[1], "%.3f" % popt[2])
        return distance
    except:
        print(figname)
        return figname


def roofline_test():
    with open(MODEL, 'r') as f:
        data = json.load(f)

    errs = []
    with open('sorted_errors.txt', 'w') as err_file:
        for m in tqdm(data):
            res = roofline_model(data[m][0], m)
            errs.extend(res)
        errs.sort()
        for err in errs:
            err_file.write(f"{err:.4f}\n")
    print(f"len: {len(errs)}, mean: {np.mean(errs)}, std: {np.std(errs)}, curve: {len(data)}")


# Get each operation's throughput individually and calculate weighted average
def dpa_predictor_naive_op_combine(model, ops, real):
    
    points = []
    total = 0
    for op in ops:
        line_name = f'{op[0]}_xx{op[1]}xx_{op[2]}_{op[3]}'
        X = [int(k) for k in model[line_name][0].keys()]
        values = [float(k) for k in model[line_name][0].values()]
        Y = [X[i]*values[i] for i in range(len(X))]
        popt, pcov = curve_fit(rf_func, X[1:], Y[1:], bounds=(0, np.inf))
        pred = rf_func(op[4], *popt)
        points.append((pred, op[4]))
        total += op[4]
    weight = [p[1]/total for p in points]
    pred = 1/sum([w/p[0] for p, w in zip(points, weight)])/total
    err = abs(pred-real)/real
    print(f'pred: {pred:.2f}, real: {real}, err: {err:.2f}')
    return pred, err


# Combine the roofline of each operation and calculate weighted average
def dpa_predictor_naive_curve_combine(model, ops, real):

    points = []
    total = 0
    for op in ops:
        line_name = f'{op[0]}_xx{op[1]}xx_{op[2]}_{op[3]}'
        X = [int(k) for k in model[line_name][0].keys()]
        values = [float(k) for k in model[line_name][0].values()]
        Y = [X[i]*values[i] for i in range(len(X))]
        popt, pcov = curve_fit(rf_func, X[1:], Y[1:], bounds=(0, np.inf))
        pred = rf_func(X[1:], *popt)
        points.append((pred, op[4]))
        total += op[4]
    weight = [p[1]/total for p in points]
    newX = X[1:]
    newY = [0] * len(newX)
    for i in range(len(points)):
        for j in range(len(newY)):
            newY[j] += weight[i]/points[i][0][j]
    finalY = [1/y for y in newY]
    popt, pcov = curve_fit(rf_func, newX, finalY, bounds=(0, np.inf))
    pred = rf_func(total, *popt)/total
    err = abs(pred-real)/real
    print(f'pred: {pred:.2f}, real: {real}, err: {err:.2f}')
    return pred, err


def random_memory_predictor_debug():
    
    with open(MODEL, 'r') as f:
        model = json.load(f)

    ops = [
        [254, 6, "64.0MB", "32B", 4],
        [254, 2, "2.0MB", "32B", 16]
    ]
    real = 8.64

    # dpa_predictor_naive_op_combine(model, ops, real)
    dpa_predictor_naive_curve_combine(model, ops, real)


def random_memory_predictor(app, algo='combine_op'):
    
    opt_map = {
        2: 'read_dpa_random', 4: 'write_dpa_random',
        6: 'read_arm_random', 8: 'write_arm_random',
        10: 'atomic_read_dpa_random', 12: 'atomic_write_dpa_random',
        14: 'atomic_read_arm_random', 16: 'atomic_write_arm_random'
    }

    with open(MODEL, 'r') as f:
        model = json.load(f)

    errs = []
    debug = []
    for logfile in os.listdir(LOG_DIR):
        if logfile.startswith(app):
            with open(os.path.join(LOG_DIR, logfile), 'r') as f:
                for line in f.readlines():
                    if line.startswith('DPA'):
                        ops = []
                        tks = line.split()
                        nThread = int(tks[2].strip(','))
                        parsed_list = literal_eval(''.join(tks[5:]))
                        for item in parsed_list:
                            params = item.strip('--op').split(',')
                            if nThread == 128:
                                workSize = int(params[1]) * nThread / 1024
                            else:
                                workSize = int(params[1]) * (2 ** round(log2(nThread))) / 1024
                            if workSize > 1024:
                                workSizeRange = f"{round(workSize/1024)}.0MB"
                            else:
                                workSizeRange = f"{workSize}KB"
                            opt_size = f'{int(params[3])*8}B'
                            ops.append((nThread, int(params[0]), workSizeRange, opt_size, int(params[2])))
                    elif line.startswith('tx'):
                        real = float(line.split()[6])
                        if algo == 'combine_op':
                            pred, err = dpa_predictor_naive_op_combine(model, ops, real)
                        else:
                            pred, err = dpa_predictor_naive_curve_combine(model, ops, real)
                        errs.append(err)
                        ops = [(op[0], op[1], opt_map[op[1]], op[2], op[3], op[4]) for op in ops]
                        debug.append({'ops': ops, 'real': real, 'pred': pred, 'err': err})
    print(f"len: {len(errs)}, mean: {np.mean(errs)}, std: {np.std(errs)}")

    with open('predictor.json', 'w') as f:
        json.dump(debug, f, indent=4)


if __name__ == '__main__':

    print(__file__)
    
    roofline_test()
    # random_memory_predictor_debug()
    # random_memory_predictor('random_memory', algo='combine_op')
    # random_memory_predictor('random_memory', algo='combine_curve')