import os
import math
import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit
from matplotlib.font_manager import json_dump, json_load
import argparse
import sys
import json


# X = [1, 2, 3]
X = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
MODEL = 'model.json'
CASE_DIR = 'cases'


def rf_func(x, a, b, c):
    return x/(a+c*np.exp(-b/x)*x)


def predictor_load_models(model_file):
    if os.path.exists(model_file):
        mdata = json_load(model_file)
    else:
        raise Exception('No models found')
    models = {}
    # collect individual models
    for op in ['rb', 'wb', 'ra', 'wa']:
        for m in ['imem', 'emem']:
            grp = m[0]+op
            models[grp] = {}
            # byte width
            for b in [1, 2, 4, 8, 16, 32]:
                models[grp][b*4] = {}
                # array size: `i` represents number of words (4 bytes unit)
                for i in [1, 2, 4, 8, 1024, 4096, 8192, 65536, 65536*128]:
                    d_name = 'rf_opt_b%d_%s%s_n2^%d_b25' % (
                        b*4, m[0], op, int(math.log2(i)))
                    if d_name not in mdata:
                        continue
                    modl = mdata[d_name]
                    models[grp][b*4][d_name] = modl
    return models


# select the nearest roofline from our model sets
def predictor_guess_line(models, op, bnum, vrgn):
    min_high = math.pow(2, 23)
    min_high_line = None
    high = 0
    for line in models[op][bnum]:
        i_0, i_1 = line.split('_')[4].strip('n').split('^')
        vr = math.pow(int(i_0), int(i_1))
        if vr > high:
            high = vr
            high_line = line
        if vr >= vrgn and vr < min_high:
            min_high = vr
            min_high_line = line
    return min_high_line if min_high_line else high_line


def predictor_combine_op(roofs, op_cnt):
    Y = [0] * len(X)
    for gl in roofs:
        for i in range(len(X)):
            # gl = (line_name, operate num, line_model)
            tmp_y = rf_func(X[i], float(gl[2]['a']), float(
                gl[2]['b']), float(gl[2]['c']))
            Y[i] += ( 1/tmp_y ) * ( gl[1]/op_cnt )
    return [1/y for y in Y]


def predictor_combine_op2(roofs, op_cnt):
    CX = [0] * len(X)
    CY = [0] * len(CX)
    for gl in roofs:
        TMP_X = gl[2]['x_rf']
        for i in range(len(TMP_X)):
            # gl = (line_name, operate num, line_model)
            tmp_y = rf_func(TMP_X[i], float(gl[2]['a']), float(
                gl[2]['b']), float(gl[2]['c']))
            CX[i] += TMP_X[i] * ( gl[1]/op_cnt )
            CY[i] += ( 1/tmp_y ) * ( gl[1]/op_cnt )
    return CX, [1/y for y in CY]


def predictor_combine_eng(eng):
    comb_cnt = 0
    Y = [0] * len(X)
    for rw in eng:
        # rw: (op_cnt, Y)
        comb_cnt += eng[rw][0]
    for rw in eng:
        for i in range(len(X)):
            Y[i] += ( 1/eng[rw][1][i] ) * ( eng[rw][0]/comb_cnt )
    return comb_cnt, [1/y for y in Y]


def predictor_combine_eng2(eng):
    comb_cnt = 0
    CX = [0] * len(X)
    CY = [0] * len(CX)
    for rw in eng:
        # rw: (op_cnt, Y)
        comb_cnt += eng[rw][0]
    for rw in eng:
        for i in range(len(CX)):
            CX[i] += eng[rw][1][i] * ( eng[rw][0]/comb_cnt )
            CY[i] += ( 1/eng[rw][2][i] ) * ( eng[rw][0]/comb_cnt )
    return comb_cnt, CX, [1/y for y in CY]


def predictor_combine_emem(engs):
    if 'ea' in engs and 'eb' in engs:
        comb_cnt = engs['ea'][0] + engs['eb'][0]
        Y = [0] * len(X)
        for e in ['ea', 'eb']:
            for i in range(len(X)):
                Y[i] += (1/engs[e][1][i]) * (engs[e][0]/comb_cnt)
        del engs['ea']
        del engs['eb']
        engs['emem'] = (comb_cnt, [1/y for y in Y])
    return engs


def predictor_combine_emem2(engs):
    if 'ea' in engs and 'eb' in engs:
        comb_cnt = engs['ea'][0] + engs['eb'][0]
        CX = [0] * len(X)
        CY = [0] * len(CX)
        for e in ['ea', 'eb']:
            for i in range(len(CX)):
                CX[i] += engs[e][1][i] * ( engs[e][0]/comb_cnt )
                CY[i] += (1/engs[e][2][i]) * (engs[e][0]/comb_cnt)
        del engs['ea']
        del engs['eb']
        engs['emem'] = (comb_cnt, CX, [1/y for y in CY])
    return engs


'''
original desc format:
    desc = {
        'irb': { b4: [ (3, 128*4) ], b16: [ (1, 1) ] },
        'iwb': { b4: [ (3, 128*4) ], b16: [ (1, 1) ] },
        'iwa': { b8: [ (2, 1) ] }
    }
transform to:
    desc = {
        'ib': {
            'r': { b4: [ (3, 128*4) ], b16: [ (1, 1) ] },
            'w': { b4: [ (3, 128*4) ], b16: [ (1, 1) ] }
        },
        'ia': {
            'w': { b4: [ (1, 1) ] }
        }
    }
'''
def predictor(desc, models, out=True):
    ops = {}
    dbg = {}
    # reformat operations
    for item in desc:
        # four memory engines in total: internal bulk, internal atomic, external bulk, external atomic
        eng = item[0] + item[2]
        op = item[1]
        if eng not in ops:
            ops[eng] = {}
            dbg[eng] = {}
        op_cnt = 0
        roofs = []
        for bnum in desc[item]:
            for l in desc[item][bnum]:
                op_cnt += l[0]
                vrgn = l[1]
                g_l = predictor_guess_line(models, item, bnum, vrgn)
                # approximate new roof rate according to operation frequency
                roofs.append((g_l, l[0], models[item][bnum][g_l]))
        Y = predictor_combine_op(roofs, op_cnt)
        ops[eng][op] = (op_cnt, Y, bnum)
        dbg[eng][op] = ops[eng][op]
    # combine rooflines
    res_eng = {}
    for eng in ops:
        # for example, combine ibr and ibw
        comb_cnt, Y = predictor_combine_eng(ops[eng])
        res_eng[eng] = (comb_cnt, Y)
        dbg[eng]['combine'] = res_eng[eng]
    res_eng = predictor_combine_emem(res_eng)
    if 'emem' in res_eng:
        dbg['emem'] = res_eng['emem']
    res = []
    for eng in res_eng:
        comb_cnt, Y = res_eng[eng]
        # calculate a new prediction line
        popt, pcov = curve_fit(rf_func, X, Y, bounds=(0, np.inf))
        pred = rf_func(comb_cnt, popt[0], popt[1], popt[2])
        res.append(pred/comb_cnt)
    pred = min(res)
    if out:
        print("predict throughput: %s Mpps" % pred)
    # return '{:.2f}'.format(pred), dbg
    return pred, dbg


def predictor2(desc, models, out=True):
    ops = {}
    dbg = {}
    # reformat operations
    for item in desc:
        # four memory engines in total: internal bulk, internal atomic, external bulk, external atomic
        eng = item[0] + item[2]
        op = item[1]
        if eng not in ops:
            ops[eng] = {}
            dbg[eng] = {}
        op_cnt = 0
        roofs = []
        for bnum in desc[item]:
            for l in desc[item][bnum]:
                op_cnt += l[0]
                vrgn = l[1]
                g_l = predictor_guess_line(models, item, bnum, vrgn)
                # approximate new roof rate according to operation frequency
                roofs.append((g_l, l[0], models[item][bnum][g_l]))
        CX, CY = predictor_combine_op2(roofs, op_cnt)
        ops[eng][op] = (op_cnt, CX, CY)
        dbg[eng][op] = ops[eng][op]
    # combine rooflines
    res_eng = {}
    for eng in ops:
        # for example, combine ibr and ibw
        comb_cnt, CX, CY = predictor_combine_eng2(ops[eng])
        res_eng[eng] = (comb_cnt, CX, CY)
        dbg[eng]['combine'] = res_eng[eng]
    res_eng = predictor_combine_emem2(res_eng)
    if 'emem' in res_eng:
        dbg['emem'] = res_eng['emem']
    res = []
    for eng in res_eng:
        comb_cnt, CX, CY = res_eng[eng]
        # calculate a new prediction line
        popt, pcov = curve_fit(rf_func, CX, CY, bounds=(0, np.inf))
        plt.figure()
        plt.scatter(CX, CY)
        TMP_X = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
        TMP_Y = rf_func(TMP_X, *popt)
        plt.plot(TMP_X, TMP_Y, 'g--',
                label='fit: a=%5.3f, b=%5.3f, c=%5.3f' % tuple(popt))
        plt.legend()
        plt.show()
        pred = rf_func(comb_cnt, popt[0], popt[1], popt[2])
        res.append(pred/comb_cnt)
    pred = min(res)
    if out:
        print("predict throughput: %s Mpps" % pred)
    # return '{:.2f}'.format(pred), dbg
    return pred, dbg


def predictor_model_evaluate(models, case_dir):
    errs = []
    flags = [0, 0]
    cntr = 0
    for case in os.listdir(case_dir):
        for file in os.listdir(os.path.join(case_dir, case)):
            if file.endswith('.json'):
                cdata = json_load(os.path.join(case_dir, case, file))
                new_ops = {}
                for op in cdata['ops']:
                    new_ops[op] = {}
                    for b in cdata['ops'][op]:
                        new_ops[op][int(b)*4] = cdata['ops'][op][b]
                pred, dbg = predictor(new_ops, models, out=False)
                # pred, dbg = predictor2(new_ops, models, out=False)
                old_pred = float(cdata['predict (Mpps)'])
                test = float(cdata['test (Mpps)'])
                err = abs(pred - test) / test
                # err = abs(pred - test)
                # old_err = abs(old_pred - test)
                errs.append(err)
                flag = 1 if pred > test else 0
                flags[flag] += 1
                # if err > old_err:
                    # cntr += 1
                # print("case: {}, new pred: {:.2f}, old pred: {}, test: {}, err: {:.2f}, flag: {}".format(
                #     case, pred, old_pred, test, err, flag))
    # print(cntr)
    # e_cntr = {"5%": 0, "10%": 0, "15%": 0, "20%": 0, "30%": 0, "50%": 0}
    # for e in errs:
    #     if e <= 0.05:
    #         e_cntr['5%'] += 1
    #     if e <= 0.1:
    #         e_cntr['10%'] += 1
    #     if e <= 0.15:
    #         e_cntr['15%'] += 1
    #     if e <= 0.2:
    #         e_cntr['20%'] += 1
    #     if e <= 0.3:
    #         e_cntr['30%'] += 1
    #     if e <= 0.5:
    #         e_cntr['50%'] += 1
    # print(e_cntr)
    # print(flags)
    errs.sort()
    for e in errs:
        print("{:.3f}".format(e))
    print(np.mean(errs))


def model_x(models_1, models_2):
    mdata_1 = json_load(models_1)
    mdata_2 = json_load(models_2)
    for m in mdata_2:
        assert(m in mdata_1)
        mdata_2[m]['x_rf'] = mdata_1[m]['x_rf']
        if int(mdata_2[m]['x_rf']) == 25:
            mdata_2[m]['x_rf'] = [1, 13, 25]
        else:
            mdata_2[m]['x_rf'] = [1, int(mdata_2[m]['x_rf']), 25]
    json_dump(mdata_2, models_2)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    parser = argparse.ArgumentParser(description="Predicts throughput based on memory access description.")
    parser.add_argument("--desc", type=str, required=True, help="JSON string of the operation description.")
    parser.add_argument("--model_file", type=str, default=MODEL, help=f"Path to the model JSON file (default: {MODEL}).")

    args = parser.parse_args()

    try:
        models = predictor_load_models(args.model_file)
    except Exception as e:
        print(f"Error loading models from {args.model_file}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        parsed_desc_from_json = json.loads(args.desc)
        
        transformed_desc = {}
        for op_type, bitwidth_dict in parsed_desc_from_json.items():
            current_op_transformed_bitwidths = {}
            for bitwidth_str_key, val_list in bitwidth_dict.items():
                if bitwidth_str_key.startswith('b') and len(bitwidth_str_key) > 1 and bitwidth_str_key[1:].isdigit():
                    numeric_part = int(bitwidth_str_key[1:]) # e.g., 'b4' -> 4
                    current_op_transformed_bitwidths[numeric_part] = val_list
                else:
                    raise ValueError(f"Invalid bitwidth key format: '{bitwidth_str_key}' in operation '{op_type}'. Expected 'bX' (e.g., 'b4').")
            if current_op_transformed_bitwidths: # Only add if there were valid bitwidths for this op_type
                transformed_desc[op_type] = current_op_transformed_bitwidths
        
        if not transformed_desc:
            raise ValueError("Parsed description is empty or resulted in no valid operations after transformation.")

    except json.JSONDecodeError as e:
        print(f"Error parsing --desc JSON string: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error transforming description: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e: 
        print(f"An unexpected error occurred while processing the description: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        prediction, _ = predictor(transformed_desc, models, out=False)
        print(f"{prediction}") # Output only the float value, which can be parsed by C++
    except Exception as e:
        print(f"Error during prediction: {e}", file=sys.stderr)
        sys.exit(1)