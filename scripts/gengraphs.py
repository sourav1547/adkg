import json
import matplotlib.pyplot as plt
import re


def dehumanize_time(timestr):
    if timestr[-3:] == 'mus': return float(timestr[0:-4])/10**6
    if timestr[-2:] == 'ms': return float(timestr[0:-3])/10**3


plt.style.use("ggplot")

with open("../.benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
tvals_provebatch = []
provebatchtimes = []

polytimes = []
polycountvals_provebatch = []

tvals_verifybatch = []
verifybatchtimes = []
for entry in logbenchmarks:
    if entry["name"].startswith("test_benchmark_batch_creation"):
        t = entry["params"]["t"]
        tvals_provebatch.append(str(t))
        provebatchtimes.append(entry["stats"]["mean"] / ((3*t+1)**2))
    if entry["name"].startswith("test_benchmark_prover_dbatch_vary_poly"):
        polycount = entry["params"]["polycount"]
        polycountvals_provebatch.append(str(polycount))
        polytimes.append(entry["stats"]["mean"] / ((3*20+1)*polycount))
    if entry["name"].startswith("test_benchmark_batch_verify"):
        t = entry["params"]["t"]
        tvals_verifybatch.append(str(t))
        verifybatchtimes.append(entry["stats"]["mean"] / (3*t+1))

#with open("../.benchmarks/Linux-CPython-3.7-64bit/0002_const.json", "r") as file:
#    constdata = file.read().replace("\n", "")
#constbenchmarks = json.loads(constdata)["benchmarks"]
#consttimes = []
#for entry in constbenchmarks:
#    if entry["name"].startswith("test_benchmark_create_wit"):
#        consttimes.append(entry["stats"]["mean"] * (3 * entry["params"]["t"] + 1))

width = 0.35
t_pos = [i for i, _ in enumerate(tvals_provebatch)]
#log_pos = [i - width / 2 for i in t_pos]
log_pos = [i for i in t_pos]
#const_pos = [i + width / 2 for i in t_pos]
plt.bar(log_pos, provebatchtimes, width, label="log")
#plt.bar(const_pos, consttimes, width, label="const")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Generation time per proof (seconds)")
plt.title("PolyCommitLog Prover Benchmarks")

plt.xticks(t_pos, tvals_provebatch)
#plt.yscale("log")
#plt.legend(loc="best")
plt.savefig("batch_prover", bbox_inches='tight')
plt.clf()

pc_pos = [i for i, _ in enumerate(polycountvals_provebatch)]
plt.bar(pc_pos, polytimes, width, label="log")
plt.xlabel("Number of polynomials")
plt.ylabel("Amortized Generation time per proof (seconds)")
plt.title("Varying polynomial count while t=20")
plt.xticks(pc_pos, polycountvals_provebatch)
plt.savefig("vary_polys", bbox_inches='tight')

plt.clf()
t_pos = [i for i, _ in enumerate(tvals_verifybatch)]
plt.bar(t_pos, verifybatchtimes, width, label="log")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Verification time per proof (seconds)")
plt.title("PolyCommitLog Verifier Benchmarks")
plt.xticks(t_pos, tvals_verifybatch)
plt.savefig("batch_verifier", bbox_inches='tight')


####### BEGIN AMT-ONLY BENCHMARKS
plt.clf()
with open("amt/vssresults.csv", "r") as file:
    lines = file.readlines()
entries = []
for line in lines[1:]:
    entry = line.split(',')
    entries.append(entry)
header = lines[0].split(',')
i=0
for item in header:
    if item == 't': t_ind = i
    if item == 'n': n_ind = i
    if item == 'avg_deal_usec': deal_ind = i
    if item == 'avg_verify_usec': ver_ind = i
    i+=1

n_arr = [entry[n_ind] for entry in entries]
deal_arr = [int(entry[deal_ind]) / int(entry[n_ind]) / 10**6 for entry in entries]
ver_arr = [int(entry[ver_ind]) / 10**6 for entry in entries]
n_pos = [i for i, _ in enumerate(n_arr)]

plt.bar(n_pos, deal_arr, width)
plt.xlabel("Total players n = 2t+1")
plt.ylabel("Amortized Deal time per recipient (seconds)")
plt.title("AMTVSS Dealer Benchmarks")
plt.xticks(n_pos, n_arr)
plt.savefig("amt_dealer", bbox_inches='tight')

plt.clf()

plt.bar(n_pos, ver_arr, width)
plt.xlabel("Total players n = 2t+1")
plt.ylabel("Verification time (seconds)")
plt.title("AMTVSS Verifier Benchmarks")
plt.xticks(n_pos, n_arr)
plt.savefig("amt_verifier", bbox_inches='tight')

######## BEGIN HYBRID BENCHMARKS
plt.clf()

amtdealtimes = []
for filename in ["amt/t1.txt", "amt/t2.txt", "amt/t5.txt", "amt/t11.txt", "amt/t21.txt", "amt/t33.txt"]:
    with open(filename, "r") as file:
        txt = file.read()
    authrootstime = dehumanize_time(re.search(r"Auth roots-of-unity eval.* per", txt).group()[:-4][26:])
    authtreetime = dehumanize_time(re.search(r"Auth accum tree.* per", txt).group()[:-4][17:])
    n = int(re.search(r"n = .* points", txt).group()[:-7][4:])
    dealtime = (authrootstime + authtreetime) / n
    amtdealtimes.append(dealtime)

n_vals = [str(3 * int(t) + 1) for t in tvals_provebatch]
n_pos = [i for i, _ in enumerate(n_vals)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]
plt.bar(pcl_pos, provebatchtimes, width, label="hb")
plt.bar(amt_pos, amtdealtimes, width, label="amt")
plt.xlabel("Total recipients (n=3t+1)")
plt.ylabel("Amortized Generation time per proof (seconds)")
plt.title("PolyCommitLog vs AMT Dealer Performance")
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.savefig("pcl vs amt", bbox_inches='tight')