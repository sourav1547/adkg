import json
import matplotlib.pyplot as plt
import re
import math


def dehumanize_time(timestr):
    if timestr[-3:] == 'mus':
        return float(timestr[0:-4]) / 10 ** 6
    if timestr[-2:] == 'ms':
        return float(timestr[0:-3]) / 10 ** 3


# Larger graph for detailed profiling
# plt.figure(figsize=(17, 3))
axis_label_size = 12
title_size = 12
color1 = "#e84a27"
color2 = "#13294b"
color3 = "#a832a8"
color4 = "#01ff2d"
tick_fontsize = 12

# Loading
with open("DataWinterfell/Linux-CPython-3.7-64bit/0029_pcl_detailed.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
tvals_provebatch = []
provebatchtimes = []
provebatchtimes_yerr = []

tvals_verifybatch = []
verifybatchtimes = []
verifybatchtimes_yerr = []
for entry in logbenchmarks:
    if entry["name"].startswith("test_benchmark_batch_creation"):
        t = entry["params"]["t"]
        tvals_provebatch.append(str(t))
        provebatchtimes.append(entry["stats"]["mean"] / (3 * t + 1) / (6 * (t + 1)))
        # provebatchtimes_yerr.append(
        #     (entry["stats"]["stddev"]**2/(3*t+1))**(1/2)*1.960/(entry["stats"]["rounds"]**(1/2)))
    if entry["name"].startswith("test_benchmark_batch_verify"):
        t = entry["params"]["t"]
        tvals_verifybatch.append(str(t))
        verifybatchtimes.append(entry["stats"]["mean"] / (6 * (t + 1)))
        # verifybatchtimes_yerr.append(
        #     (entry["stats"]["stddev"]**2/(3*t+1))**(1/2)*1.960/(entry["stats"]["rounds"]**(1/2)))

provebatchtimes = [i * 1000.0 for i in provebatchtimes]
provebatchtimes_yerr = [i * 1000.0 for i in provebatchtimes_yerr]
verifybatchtimes = [i * 1000.0 for i in verifybatchtimes]
verifybatchtimes_yerr = [i * 1000.0 for i in verifybatchtimes_yerr]

# Every entry below will have a dict of {batch_multiple, t, mean, orig_batched_stddev, confidence_yerr}
hbacss0_dummy_pcl_max_faulty_shares = []
hbacss0_dummy_pcl_one_faulty_share = []
hbacss0_dummy_pcl_all_correct = []
hbacss1_dummy_pcl_max_faulty_shares = []
hbacss1_dummy_pcl_one_faulty_share = []
hbacss1_dummy_pcl_all_correct = []
hbacss2_dummy_pcl_max_faulty_shares = []
hbacss2_dummy_pcl_one_faulty_share = []
hbacss2_dummy_pcl_all_correct = []

with open("DataWinterfell/Linux-CPython-3.7-64bit/0028_hbavss_dummy_pcl.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    batch_multiple = entry["params"]["batch_multiple"]
    t = entry["params"]["t"]
    mean = entry["stats"]["mean"]
    per_party_per_proof_mean = mean / ((3 * t + 1) * batch_multiple * (t + 1))
    per_party_per_proof_mean *= 1000.0
    orig_batched_stddev = entry["stats"]["stddev"]
    confidence_yerr = (entry["stats"]["stddev"] ** 2 / (3 * t + 1)
                       ) ** (1 / 2) * 1.960 / (entry["stats"]["rounds"] ** (1 / 2))
    confidence_yerr *= 1000.0
    dict = {"batch_multiple": batch_multiple, "t": t, "mean": mean,
            "per_party_per_proof_mean": per_party_per_proof_mean, "orig_batched_stddev": orig_batched_stddev,
            "confidence_yerr": confidence_yerr}
    if entry["name"].startswith("test_hbacss0_pcl_all_correct"):
        hbacss0_dummy_pcl_all_correct.append(dict)
    if entry["name"].startswith("test_hbacss0_pcl_one_faulty_share"):
        hbacss0_dummy_pcl_one_faulty_share.append(dict)
    if entry["name"].startswith("test_hbacss0_pcl_max_faulty_shares"):
        hbacss0_dummy_pcl_max_faulty_shares.append(dict)
    if entry["name"].startswith("test_hbacss1_pcl_all_correct"):
        hbacss1_dummy_pcl_all_correct.append(dict)
    if entry["name"].startswith("test_hbacss1_pcl_one_faulty_share"):
        hbacss1_dummy_pcl_one_faulty_share.append(dict)
    if entry["name"].startswith("test_hbacss1_pcl_max_faulty_shares"):
        hbacss1_dummy_pcl_max_faulty_shares.append(dict)
    if entry["name"].startswith("test_hbacss2_pcl_all_correct"):
        hbacss2_dummy_pcl_all_correct.append(dict)
    if entry["name"].startswith("test_hbacss2_pcl_one_faulty_share"):
        hbacss2_dummy_pcl_one_faulty_share.append(dict)
    if entry["name"].startswith("test_hbacss2_pcl_max_faulty_shares"):
        hbacss2_dummy_pcl_max_faulty_shares.append(dict)

with open("DataWinterfell/amt_benchmarks/vssresults.csv", "r") as file:
    lines = file.readlines()
entries = []
for line in lines[1:]:
    entry = line.split(',')
    entries.append(entry)
header = lines[0].split(',')
i = 0
for item in header:
    if item == 't':
        t_ind = i
    if item == 'n':
        n_ind = i
    if item == 'avg_deal_usec':
        deal_ind = i
    if item == 'stddev_deal':
        deal_stddev_ind = i
    if item == 'avg_verify_usec':
        ver_ind = i
    if item == 'stddev_verify':
        ver_stddev_ind = i
    if item == 'avg_reconstr_wc_usec':
        amt_reconstr_wc_usec = i
    if item == 'stddev_reconstr_wc_usec':
        amt_reconstr_wc_stddev_ind = i
    if item == 'avg_reconstr_bc_usec':
        avg_reconstr_bc_usec = i
    if item == 'stddev_reconstr_bc_usec':
        avg_reconstr_bc_usec_stddev_ind = i
    i += 1

# Units are microseconds, the number of iters is 100.
ver_arr = [float(entry[ver_ind]) / (10 ** 3) for entry in entries]
ver_yerr_arr = [float(entry[ver_stddev_ind]) * 1.960 /
                (100 ** (1 / 2)) / (10 ** 3) for entry in entries]

n_arr = [(entry[n_ind]) for entry in entries]

deal_arr = [float(entry[deal_ind]) / (10 ** 3.0) / int(n_arr[i])
            for i, entry in enumerate(entries)]
deal_yerr_arr = [float(entry[deal_stddev_ind]) * 1.960 / (100 ** (1 / 2)) / (10 ** 3.0) / int(n_arr[i])
                 for i, entry in enumerate(entries)]
amt_reconstr_wc_arr = [
    float(entry[amt_reconstr_wc_usec]) / (10 ** 3) for entry in entries]
amt_reconstr_bc_arr = [
    float(entry[avg_reconstr_bc_usec]) / (10 ** 3) for entry in entries]

# plotting_reconstr_wc_arr = []
# plotting_reconstr_bc_arr = []
# plotting_ver_yerr_arr = []
amt_plotting_ver_arr = []
amt_plotting_n_arr = []
for elem in tvals_verifybatch:
    index = n_arr.index(str(int(elem) * 3 + 1))
    amt_plotting_ver_arr.append(ver_arr[index])
    amt_plotting_n_arr.append(n_arr[index])
    # plotting_ver_yerr_arr.append(ver_yerr_arr[index])
    # plotting_reconstr_wc_arr.append(amt_reconstr_wc_arr[index])
    # plotting_reconstr_bc_arr.append(amt_reconstr_bc_arr[index])

n_vals = [str(3 * int(t) + 1) for t in tvals_provebatch]
n_pos = [i for i, _ in enumerate(n_vals)]

# ----------------------------------------------------------------------
# PCL Verification
plt.figure(figsize=(10, 3))
plt.clf()
plt.plot(verifybatchtimes[::2], linestyle='-', marker='o',
         color=color1, label="hbPolyCommit")
plt.plot(amt_plotting_ver_arr[::2], linestyle='-', marker='o',
         color=color2, label="AMT PC")
# plt.errorbar(amt_plotting_n_arr, verifybatchtimes,
#              yerr=verifybatchtimes_yerr, fmt='none')
# plt.errorbar(amt_plotting_n_arr, amt_plotting_ver_arr,
#              yerr=plotting_ver_yerr_arr, fmt='none')
plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Verification time per proof (ms)", fontsize=axis_label_size)
plt.title("hbPolyCommit vs AMT PC Verification Performance",
          fontsize=title_size)
plt.xticks(n_pos[:len(amt_plotting_n_arr[::2])], amt_plotting_n_arr[::2])
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("gen_graphs/pcl_vs_amt_verification.png", bbox_inches='tight')
plt.savefig("gen_graphs/pcl_vs_amt_verification.pdf", bbox_inches='tight')

# -----------------------------------------------------------------------------------------------
# PCL proof generation
plt.figure(figsize=(10, 3))
plotting_deal_arr = []
plotting_deal_yerr_arr = []
for elem in tvals_provebatch:
    index = n_arr.index(str(int(elem) * 3 + 1))
    plotting_deal_arr.append(deal_arr[index])
    plotting_deal_yerr_arr.append(deal_yerr_arr[index])

plt.clf()
plt.plot(provebatchtimes[::2], linestyle='-', marker='o',
         color=color1, label="hbPolyCommit")
plt.plot(plotting_deal_arr[::2], linestyle='-', marker='o',
         color=color2, label="AMT PC")
# plt.errorbar(amt_plotting_n_arr, provebatchtimes,
#              yerr=provebatchtimes_yerr, fmt='none')
# plt.errorbar(amt_plotting_n_arr, plotting_deal_arr,
#              yerr=plotting_deal_yerr_arr, fmt='none')
plt.xlabel("Total players (N=3t+1)", fontsize=axis_label_size)
plt.ylabel("Prover computation per proof (ms)",
           fontsize=axis_label_size)
plt.title("hbPolyCommit vs AMT PC Proof Generation", fontsize=title_size)
plt.xticks(n_pos[:len(amt_plotting_n_arr[::2])], amt_plotting_n_arr[::2])
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("gen_graphs/pcl_vs_amt_prove_generation.png", bbox_inches='tight')
plt.savefig("gen_graphs/pcl_vs_amt_prove_generation.pdf", bbox_inches='tight')

# -------------------------------------------------------------------------------------

# Fixed multiple

fixed_multuple = 6
t_extracted = [1, 2, 5, 10, 22, 42]


def draw_fixed_multiple(fixed_multuple, scenario_name, file_name,
                        td_t_c0, td_per_party_per_proof_mean_c0,
                        td_per_party_per_proof_mean_c1, td_per_party_per_proof_mean_c2):
    plt.clf()
    plt.figure(figsize=(8, 3))
    n_vals = [str(3 * i + 1) for i in td_t_c0]
    t_pos = [i for i, _ in enumerate(n_vals)]

    plt.plot(td_per_party_per_proof_mean_c0, linestyle='-', marker='o',
             color=color1, label="HbACSS0")
    plt.plot(td_per_party_per_proof_mean_c1, linestyle='-', marker='o',
             color=color2, label="HbACSS1")
    plt.plot(td_per_party_per_proof_mean_c2, linestyle='-', marker='o',
             color=color3, label="HbACSS2")

    plt.xlabel("Total players (N=3t+1)", fontsize=axis_label_size)
    plt.ylabel("Comp per value shared (ms)",
               fontsize=axis_label_size)
    plt.title("Amortized baseline costs when batch_size=6*(t+1) under " + scenario_name,
              fontsize=title_size)
    plt.xticks(t_pos, n_vals)
    plt.legend(loc="best")
    plt.xticks(fontsize=tick_fontsize)
    plt.yticks(fontsize=tick_fontsize)
    plt.ylim(0)
    plt.savefig("gen_graphs/" + file_name + ".png",
                bbox_inches='tight')
    plt.savefig("gen_graphs/" + file_name + ".pdf",
                bbox_inches='tight')


td_points_c0 = []
td_points_c1 = []
td_points_c2 = []

for i in hbacss0_dummy_pcl_max_faulty_shares:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c0.append(
            (i['per_party_per_proof_mean'], i['t']))

for i in hbacss1_dummy_pcl_max_faulty_shares:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c1.append(
            (i['per_party_per_proof_mean'], i['t']))

for i in hbacss2_dummy_pcl_max_faulty_shares:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c2.append(
            (i['per_party_per_proof_mean'], i['t']))

# Sorting
td_points_c0 = sorted(td_points_c0, key=lambda x: x[1])
td_points_c1 = sorted(td_points_c1, key=lambda x: x[1])
td_points_c2 = sorted(td_points_c2, key=lambda x: x[1])

td_per_party_per_proof_mean_c0 = [i[0] for i in td_points_c0]
td_t_c0 = [i[1] for i in td_points_c0]
td_per_party_per_proof_mean_c1 = [i[0] for i in td_points_c1]
td_t_c1 = [i[1] for i in td_points_c1]
td_per_party_per_proof_mean_c2 = [i[0] for i in td_points_c2]
td_t_c2 = [i[1] for i in td_points_c2]

draw_fixed_multiple(fixed_multuple, "max faulty shares", "fix_multiple_pcl_max_faulty_shares", td_t_c0,
                    td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1, td_per_party_per_proof_mean_c2)

td_points_c0 = []
td_points_c1 = []
td_points_c2 = []

for i in hbacss0_dummy_pcl_all_correct:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c0.append(
            (i['per_party_per_proof_mean'], i['t']))

for i in hbacss1_dummy_pcl_all_correct:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c1.append(
            (i['per_party_per_proof_mean'], i['t']))

for i in hbacss2_dummy_pcl_all_correct:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c2.append(
            (i['per_party_per_proof_mean'], i['t']))

# Sorting
td_points_c0 = sorted(td_points_c0, key=lambda x: x[1])
td_points_c1 = sorted(td_points_c1, key=lambda x: x[1])
td_points_c2 = sorted(td_points_c2, key=lambda x: x[1])

td_per_party_per_proof_mean_c0 = [i[0] for i in td_points_c0]
td_t_c0 = [i[1] for i in td_points_c0]
td_per_party_per_proof_mean_c1 = [i[0] for i in td_points_c1]
td_t_c1 = [i[1] for i in td_points_c1]
td_per_party_per_proof_mean_c2 = [i[0] for i in td_points_c2]
td_t_c2 = [i[1] for i in td_points_c2]

draw_fixed_multiple(fixed_multuple, "all correct", "fix_multiple_pcl_all_correct", td_t_c0,
                    td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1, td_per_party_per_proof_mean_c2)

# -------------------------------------------------------------------------------------

# Extrapolated e2e time.

fixed_multiple = 6
t_extracted = [1, 2, 5, 10, 22, 42]


def draw_fixed_multiple_e2e(fixed_multuple, scenario_name, file_name,
                            td_n_c0, td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1,
                            td_per_party_per_proof_mean_c2, td_per_party_per_proof_mean_c3):
    plt.clf()
    plt.figure(figsize=(8, 3))
    n_vals = [str(i) for i in td_n_c0]
    t_pos = [i for i, _ in enumerate(n_vals)]

    plt.plot(td_per_party_per_proof_mean_c0, linestyle='-', marker='o',
             color=color1, label="HbACSS0+hbPolyCommit")
    plt.plot(td_per_party_per_proof_mean_c1, linestyle='-', marker='o',
             color=color2, label="HbACSS0+AMT")
    plt.plot(td_per_party_per_proof_mean_c2, linestyle='-', marker='o',
             color=color3, label="HbACSS1+AMT")
    plt.plot(td_per_party_per_proof_mean_c3, linestyle='-', marker='o',
             color=color4, label="HbACSS2+hbPolyCommit")

    plt.xlabel("Total players (N=3t+1)", fontsize=axis_label_size)
    plt.ylabel("Comp per value shared (ms)",
               fontsize=axis_label_size)
    plt.title("Estimated end-to-end time per value shared with " + scenario_name,
              fontsize=title_size)
    plt.xticks(t_pos, n_vals)
    plt.legend(loc="best")
    plt.xticks(fontsize=tick_fontsize)
    plt.yticks(fontsize=tick_fontsize)
    plt.ylim(0)
    plt.savefig("gen_graphs/" + file_name + ".png",
                bbox_inches='tight')
    plt.savefig("gen_graphs/" + file_name + ".pdf",
                bbox_inches='tight')



# # Loading the data for batch size specific to hbacss2
# with open("DataWinterfell/Linux-CPython-3.7-64bit/0022_hbavss2_only_pcl.json", "r") as file:
#     logdata = file.read().replace("\n", "")
# logbenchmarks = json.loads(logdata)["benchmarks"]
# hbacss2_tvals_provebatch = []
# hbacss2_provebatchtimes = []
# hbacss2_tvals_verifybatch = []
# hbacss2_verifybatchtimes = []
# for entry in logbenchmarks:
#     if entry["name"].startswith("test_hbacss2_size_benchmark_batch_creation"):
#         t = entry["params"]["t"]
#         hbacss2_tvals_provebatch.append(str(t))
#         hbacss2_provebatchtimes.append(entry["stats"]["mean"] / (3 * t + 1) / t)
#     if entry["name"].startswith("test_hbacss2_size_benchmark_batch_verify"):
#         t = entry["params"]["t"]
#         hbacss2_tvals_verifybatch.append(str(t))
#         hbacss2_verifybatchtimes.append(entry["stats"]["mean"] / t)
# hbacss2_provebatchtimes = [i * 1000.0 for i in hbacss2_provebatchtimes]
# hbacss2_verifybatchtimes = [i * 1000.0 for i in hbacss2_verifybatchtimes]
# print(hbacss2_provebatchtimes)
# print(hbacss2_verifybatchtimes)

# Clear the data
hbacss2_dummy_pcl_all_correct = []
hbacss2_dummy_pcl_max_faulty_shares = []
# Loading the data for hbacss2 with batch size t*(t+1)
with open("DataWinterfell/Linux-CPython-3.7-64bit/0031_hbacss2_dummy_pcl.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    t = entry["params"]["t"]
    mean = entry["stats"]["mean"]
    per_party_per_proof_mean = mean / ((3 * t + 1) * 6 * (t+1) * (t + 1))
    per_party_per_proof_mean *= 1000.0
    orig_batched_stddev = entry["stats"]["stddev"]
    dict = {"t": t, "mean": mean,
            "per_party_per_proof_mean": per_party_per_proof_mean, "orig_batched_stddev": orig_batched_stddev}
    if entry["name"].startswith("test_hbacss2_pcl_all_correct"):
        hbacss2_dummy_pcl_all_correct.append(dict)
    if entry["name"].startswith("test_hbacss2_pcl_max_faulty_shares"):
        hbacss2_dummy_pcl_max_faulty_shares.append(dict)


# Clear the data
hbacss1_dummy_pcl_all_correct = []
hbacss1_dummy_pcl_max_faulty_shares = []
# Loading the data for hbacss1 with batch size t*(t+1)
with open("DataWinterfell/Linux-CPython-3.7-64bit/0003_hbacss1_dummy_pcl.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    t = entry["params"]["t"]
    mean = entry["stats"]["mean"]
    per_party_per_proof_mean = mean / ((3 * t + 1) * 6 * (t+1) * (t + 1))
    per_party_per_proof_mean *= 1000.0
    orig_batched_stddev = entry["stats"]["stddev"]
    dict = {"t": t, "mean": mean,
            "per_party_per_proof_mean": per_party_per_proof_mean, "orig_batched_stddev": orig_batched_stddev}
    if entry["name"].startswith("test_hbacss1_pcl_all_correct"):
        hbacss1_dummy_pcl_all_correct.append(dict)
    if entry["name"].startswith("test_hbacss1_pcl_max_faulty_shares"):
        hbacss1_dummy_pcl_max_faulty_shares.append(dict)


td_points_c0 = []
td_points_c1 = []
td_points_c2 = []
for i in hbacss0_dummy_pcl_all_correct:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c0.append(
            (i['per_party_per_proof_mean'], i['t']))
for i in hbacss1_dummy_pcl_all_correct:
    if i['t'] in t_extracted:
        td_points_c1.append(
            (i['per_party_per_proof_mean'], i['t']))
for i in hbacss2_dummy_pcl_all_correct:
    if i['t'] in t_extracted:
        td_points_c2.append(
            (i['per_party_per_proof_mean'], i['t']))
# Sorting
td_points_c0 = sorted(td_points_c0, key=lambda x: x[1])
td_points_c1 = sorted(td_points_c1, key=lambda x: x[1])
td_points_c2 = sorted(td_points_c2, key=lambda x: x[1])


td_per_party_per_proof_mean_c0 = []
td_per_party_per_proof_mean_c1 = []
td_per_party_per_proof_mean_c2 = []
td_per_party_per_proof_mean_c3 = []
td_n = []

for i, elem in enumerate(td_points_c0):
    # Calculating hbacss0 + hbPolyCommit
    t = elem[1]
    n = 3 * t + 1
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c0.append(
        provebatchtimes[index] + verifybatchtimes[index] + td_points_c0[i][0])

    # Calculating hbacss0 + amt
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c1.append(td_points_c0[i][0] + plotting_deal_arr[index] + amt_plotting_ver_arr[index])

    # Calculating hbacss1 + amt
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c2.append(td_points_c1[i][0] + plotting_deal_arr[index] + amt_plotting_ver_arr[index])

    # Calculating hbacss2 + hbPolyCommit
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    redundancy_overhead = n / (t + 1)
    td_per_party_per_proof_mean_c3.append(
        (provebatchtimes[index] + verifybatchtimes[index]) * redundancy_overhead + td_points_c2[i][0])
    td_n.append(3 * t + 1)

draw_fixed_multiple_e2e(fixed_multuple, "no errors", "e2e_pcl_all_correct", td_n,
                        td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1, td_per_party_per_proof_mean_c2, td_per_party_per_proof_mean_c3)

td_points_c0 = []
td_points_c1 = []
td_points_c2 = []
for i in hbacss0_dummy_pcl_max_faulty_shares:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c0.append(
            (i['per_party_per_proof_mean'], i['t']))
for i in hbacss1_dummy_pcl_max_faulty_shares:
    if i['t'] in t_extracted:
        td_points_c1.append(
            (i['per_party_per_proof_mean'], i['t']))
for i in hbacss2_dummy_pcl_max_faulty_shares:
    if i['t'] in t_extracted:
        td_points_c2.append(
            (i['per_party_per_proof_mean'], i['t']))
# Sorting
td_points_c0 = sorted(td_points_c0, key=lambda x: x[1])
td_points_c1 = sorted(td_points_c1, key=lambda x: x[1])
td_points_c2 = sorted(td_points_c2, key=lambda x: x[1])

td_per_party_per_proof_mean_c0 = []
td_per_party_per_proof_mean_c1 = []
td_per_party_per_proof_mean_c2 = []
td_per_party_per_proof_mean_c3 = []
td_n = []

for i, elem in enumerate(td_points_c0):
    t = elem[1]
    n = 3 * t + 1
    # Calculating hbacss0 + hbPolyCommit
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c0.append(
        provebatchtimes[index] + verifybatchtimes[index] + verifybatchtimes[index] * ((2 * t + 1) / n) + (t + 1) * (
                    t / n) * verifybatchtimes[index] + td_points_c0[i][0])

    # Calculating hbacss0 + amt
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c1.append(
        plotting_deal_arr[index] + amt_plotting_ver_arr[index] + amt_plotting_ver_arr[index] * ((2 * t + 1) / n) + (
                    t + 1) * (t / n) * amt_plotting_ver_arr[index] + td_points_c0[i][0])
    
    # Calculating hbacss1 + amt
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    td_per_party_per_proof_mean_c2.append(
        plotting_deal_arr[index] + amt_plotting_ver_arr[index] + amt_plotting_ver_arr[index] * ((2 * t + 1) / n) + \
            ((t + 1) / n) *amt_plotting_ver_arr[index] + td_points_c1[i][0])

    # Calculating hbacss2 + hbPolyCommit
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    redundancy_overhead = n / (t + 1)
    td_per_party_per_proof_mean_c3.append((provebatchtimes[index] + verifybatchtimes[index] + verifybatchtimes[
        index] * (2 * t + 1) / n + ((t + 1) / n) * verifybatchtimes[index]) * redundancy_overhead + td_points_c2[i][0])
    td_n.append(3 * t + 1)

draw_fixed_multiple_e2e(fixed_multuple, "max faulty shares", "e2e_pcl_max_faulty_shares", td_n,
                        td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1, td_per_party_per_proof_mean_c2, td_per_party_per_proof_mean_c3)

# -----------------------

# Checking the actual runtime to make sure our calculations are correct
# hbacss0_actual_pcl_max_faulty_shares = []
# hbacss0_actual_pcl_all_correct = []
# hbacss2_actual_pcl_max_faulty_shares = []
# hbacss2_actual_pcl_all_correct = []

# with open("DataWinterfell/Linux-CPython-3.7-64bit/0030_hbavss_actual_pcl.json", "r") as file:
#     logdata = file.read().replace("\n", "")
# logbenchmarks = json.loads(logdata)["benchmarks"]
# for entry in logbenchmarks:
#     batch_multiple = entry["params"]["batch_multiple"]
#     t = entry["params"]["t"]
#     mean = entry["stats"]["mean"]

#     if entry["name"].startswith("test_hbacss0"):
#         per_party_per_proof_mean = mean / ((3 * t + 1) * batch_multiple * (t + 1))
#     if entry["name"].startswith("test_hbacss2"):
#         per_party_per_proof_mean = mean / ((3 * t + 1) * batch_multiple * (t + 1) * (t + 1))

#     per_party_per_proof_mean *= 1000.0
#     dict = {"batch_multiple": batch_multiple, "t": t, "mean": mean,
#             "per_party_per_proof_mean": per_party_per_proof_mean}

#     if entry["name"].startswith("test_hbacss0_actual_pcl_all_correct"):
#         hbacss0_actual_pcl_all_correct.append(dict)
#     if entry["name"].startswith("test_hbacss0_actual_pcl_max_faulty_shares"):
#         hbacss0_actual_pcl_max_faulty_shares.append(dict)
#     if entry["name"].startswith("test_hbacss2_actual_pcl_all_correct"):
#         hbacss2_actual_pcl_all_correct.append(dict)
#     if entry["name"].startswith("test_hbacss2_actual_pcl_max_faulty_shares"):
#         hbacss2_actual_pcl_max_faulty_shares.append(dict)



def draw_yield(file_name,
                            td_n_c0, td_per_party_per_proof_mean_c0, td_per_party_per_proof_mean_c1,
                            td_per_party_per_proof_mean_c2):
    plt.clf()
    plt.figure(figsize=(8, 3))
    n_vals = [str(i) for i in td_n_c0]
    t_pos = [i for i, _ in enumerate(n_vals)]

    plt.plot(td_per_party_per_proof_mean_c0, linestyle='-', marker='o',
             color=color1, label="t crashes")
    plt.plot(td_per_party_per_proof_mean_c1, linestyle='-', marker='o',
             color=color2, label="t/2 crashes")
    plt.plot(td_per_party_per_proof_mean_c2, linestyle='-', marker='o',
             color=color3, label="0 crashes")

    plt.xlabel("Total players (N=3t+1)", fontsize=axis_label_size)
    plt.ylabel("Comp per input mask (ms)",
               fontsize=axis_label_size)
    plt.title("Input Mask Compute Time",fontsize=title_size)
    plt.xticks(t_pos, n_vals)
    plt.legend(loc="best")
    plt.xticks(fontsize=tick_fontsize)
    plt.yticks(fontsize=tick_fontsize)
    plt.ylim(0)
    plt.savefig("gen_graphs/" + file_name + ".png",
                bbox_inches='tight')
    plt.savefig("gen_graphs/" + file_name + ".pdf",
                bbox_inches='tight')



td_points_c0 = []
for i in hbacss0_dummy_pcl_all_correct:
    if i['batch_multiple'] == fixed_multuple and i['t'] in t_extracted:
        td_points_c0.append(
            (i['per_party_per_proof_mean'], i['t']))
# Sorting
td_points_c0 = sorted(td_points_c0, key=lambda x: x[1])


yield2tp1 = []
yield2_5tp1 = []
yield3tp1 = []
td_per_party_per_proof_mean_c2 = []
td_n = []

for i, elem in enumerate(td_points_c0):
    t = elem[1]
    n = 3*t+1
    # Calculating hbacss0 + hbPolyCommit
    index = amt_plotting_n_arr.index(str(3 * t + 1))
    hbacss0_time = provebatchtimes[index] + verifybatchtimes[index] + (t+1) * (t/n) * verifybatchtimes[index] + td_points_c0[i][0]
    yield2tp1.append(hbacss0_time * (2*t+1)/(t+1))
    yield2_5tp1.append(hbacss0_time * (2.5*t+1)/(1.5*t+1))
    yield3tp1.append(hbacss0_time * (3*t+1)/(2*t+1))
    td_n.append(3 * t + 1)
    if n == 31:
        print(1000 / (hbacss0_time * (3*t+1)/(2*t+1)))

draw_yield("input_mask_yield", td_n, yield2tp1, yield2_5tp1, yield3tp1)