import secrets
import time
import matplotlib.pyplot as plt
from finalproject import setup, add_element, prove_membership, delete_element, verify
# https://hippiehug.readthedocs.io/en/latest/
from hippiehug import Tree

def createGraph(sizes,acuLst,merkleLst):
    plt.plot(sizes, acuLst, label='accumulator')  # plotting t, a separately
    plt.plot(sizes, merkleLst, label='merkle')  # plotting t, b separately
    plt.xlabel('Set Size')
    plt.ylabel('Time(s)')
    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
    plt.show()


def testAccumulator(xLst):
    n, A0, S = setup()
    A = A0
    for x in xLst:
        A = add_element(A, S, x, n)


def testMerkle(xLst):
    t = Tree()
    for x in xLst:
        t.add(x)


def createRandomSet(size):
    result = []
    for index in range(0,size):
        random = secrets.randbelow(pow(2, 256))
        result.append(random)
    return result


def testRuntime(sizes):
    acuLst = []
    merkleLst = []
    merkleEvidenceLst = []
    acuEvidenceLst = []
    # initialize merkle ds
    for size in sizes:
        # initialize acu ds
        n, A0, S = setup()
        A = A0
        merkleTree = Tree()
        randomElements = createRandomSet(size)
        startAcu = int(time.time())
        # add elements to Acumulatur
        for element in randomElements:
            A = add_element(A, S, element, n)
        endAcu = int(time.time())
        totalAcu = endAcu-startAcu
        acuLst.append(totalAcu)

        startMerkle = int(time.time())
        # add elements to Merkle
        for element in randomElements:
            merkleTree.add(str(element).encode())
        endMerkle = int(time.time())
        totalMerkle = endMerkle-startMerkle
        merkleLst.append(totalMerkle)

        # # Creating Proofs
        # startAcu = int(time.time())
        # for element in randomElements:
        #     prove_membership(A0,S,element,n)
        # endAcu = int(time.time())
        # totalAcu = endAcu - startAcu
        # acuEvidenceLst.append(totalAcu)
        #
        # startMerkle = int(time.time())
        # for element in randomElements:
        #     merkleTree.evidence(str(element).encode())
        # endMerkle = int(time.time())
        # totalMerkle = endMerkle - startMerkle
        # merkleEvidenceLst.append(totalMerkle)

    createGraph(sizes, acuLst, merkleLst)


sizes = [2,4,8,16,32,64,128,256,512,1024,2048,4096]
# sizes = [2,4,8,16,32,64,128,256]

testRuntime(sizes)



