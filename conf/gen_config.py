import sys
import os 
import glob

def delete():
    files = glob.glob('conf/adkg/*')
    for f in files:
        os.remove(f)

def new(n):
    peers= []
    ip = "172.17.0.2"
    port = 13000
    for i in range(n):
        peers.append(ip+":"+str(port+i))
    print(peers)

    t = (n-1)//3
    for i in range(n):
        path = "conf/adkg/local."+str(i)+".json"
        with open(path, "w+") as ofile:
            ofile.write("{\n")
            ofile.write("\t\"N\": "+str(n)+",\n")
            ofile.write("\t\"t\": "+str(t)+",\n")
            ofile.write("\t\"my_id\": "+str(i)+",\n")
            ofile.write("\t\"peers\": [\n")
            j=0
            for peer in peers:
                if j < n-1:
                    ofile.write("\t\t\""+peer+"\",\n")
                else:
                    ofile.write("\t\t\""+peer+"\"\n")
                j=j+1
            ofile.write("\t]\n")
            ofile.write("}")

if __name__ == "__main__":
    n = int(sys.argv[1])
    delete()
    new(n)




    