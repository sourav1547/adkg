import phe

nodes = 128
keypairs = [phe.paillier.generate_paillier_keypair() for _ in range(nodes)]
public_keys, private_keys = [[keypairs[i][j] for i in range(nodes)] for j in range(2)]


ofile = open("keys", 'w')
for i in range(nodes):
    ofile.write(str(private_keys[i].public_key.n)+" "+str(private_keys[i].p)+" "+str(private_keys[i].q)+"\n")
ofile.close()
