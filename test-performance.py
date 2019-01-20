import hashlib
import secrets
import time
import matplotlib.pyplot as plt
from finalproject import setup, add_element, prove_membership, delete_element, verify_membership,add_elements
from operator import truediv

# https://github.com/Tierion/pymerkletools
import merkletools

# def createTwoGraphs(x1,y1,x2,y2,title,label1,label2):
#     f, axarr = plt.subplots(2, sharex=True)
#     f.suptitle(title)
#     axarr[0].plot(x1, y1, label='accumulator')  # plotting t, a separately
#     axarr[0].plot(x2, y2, label='merkle')  # plotting t, b separately
#     axarr[0].legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#     axarr[0].ylabel('Time(s)')
#
#     axarr[0].plot(sizes, acuLst, label='accumulator')  # plotting t, a separately
#     axarr[0].plot(sizes, merkleLst, label='merkle')  # plotting t, b separately
#     axarr[0].legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#     axarr[0].ylabel('Time(s)')



def createGraph(sizes,acuLst,merkleLst,title):
    plt.title(title)
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


# def testMerkle(xLst):
#     t = Tree()
#     for x in xLst:
#         t.add(x)


def createRandomSet(size):
    result = []
    for index in range(0,size):
        random = secrets.randbelow(pow(2, 256))
        result.append(random)
    return result


def testRuntime(sizes):
    acuLstTiming = []
    merkleLstTiming = []
    acuEvidenceTimingLst = []
    merkleEvidenceTimingLst = []
    acuVerifyTimingLst = []
    merkleVerifyTimingLst = []
    normalizeIterationsLst = []
    acuLstBatchTiming = []
    elements = createRandomSet(sizes[-1])

    # initialize merkle ds
    for size in sizes:
        # initialize ds
        n, A0, S = setup()
        A = A0
        merkleTree = merkletools.MerkleTools()
        randomElements = elements[0:size]
        acuEvidenceLst = []
        merkleEvidenceLst = []
        # print (randomElements)


        # Add - Acumulatur
        tik = time.time()
        for element in randomElements:
            A = add_element(A, S, element, n)
        tok = time.time()
        acuLstTiming.append(tok-tik)

        # Batch Add - Acumulatur
        tik = time.time()
        A = add_elements(A, S, randomElements, n)
        tok = time.time()
        acuLstBatchTiming.append(tok - tik)

        # Add - Merkle Tree
        tik = time.time()
        for element in randomElements:
            # hex_element = hashlib.sha256(element).digest().encode('hex')
            merkleTree.add_leaf(str(element),True)
        merkleTree.make_tree()
        tok = time.time()
        merkleLstTiming.append(tok-tik)

        # Evidence - Accumulator
        tik = time.time()
        for element in randomElements:
            membership = prove_membership(A0, S, element, n)
            acuEvidenceLst.append((element,membership))
        tok = time.time()
        acuEvidenceTimingLst.append(tok-tik)

        # Evidence - Merkle Tree
        tik= time.time()
        for element in range(merkleTree.get_leaf_count()):
            evidence = merkleTree.get_proof(element)
            leaf = merkleTree.get_leaf(element)
            merkleEvidenceLst.append((evidence,leaf))
        tok = time.time()
        merkleEvidenceTimingLst.append(tok-tik)

        evidenceIterations = min(100,size)
        normalizeIterationsLst.append(evidenceIterations)
        # Verify - Accumulator
        tik = time.time()
        for index in range(0,evidenceIterations):
            (element, proof) = acuEvidenceLst[index]
            result = verify_membership(A, element, S[element], proof, n)
        tok = time.time()
        acuVerifyTimingLst.append(tok-tik)

        # Verify - Merkle Tree
        tik = time.time()
        for index in range (0,evidenceIterations):
            element = merkleEvidenceLst[index]
            (evidence, root) = element
            proof = merkleTree.validate_proof(evidence, leaf, merkleTree.get_merkle_root())
        tok = time.time()
        merkleVerifyTimingLst.append(tok-tik)
        print(size)

    return sizes, acuLstTiming, merkleLstTiming,acuEvidenceTimingLst,merkleEvidenceTimingLst,acuVerifyTimingLst,merkleVerifyTimingLst,normalizeIterationsLst,acuLstBatchTiming
    # createGraph(sizes, acuLst, merkleLst, acuEvidenceLst,merkleEvidenceLst)


sizes = [16,32,64,128,256,512,1024]
sizes = [16,32,64,128,256,512]
sizes, acuLstTiming, merkleLstTiming,acuEvidenceTimingLst,merkleEvidenceTimingLst,acuVerifyTimingLst,merkleVerifyTimingLst,normalizeIterationsLst,acuLstBatchTiming = testRuntime(sizes)
fdiv1 = [float(ai)/bi for ai,bi in zip(acuEvidenceTimingLst,sizes)]
fdiv2 = [float(ai)/bi for ai,bi in zip(merkleEvidenceTimingLst,sizes)]
fdiv3 = [float(ai)/bi for ai,bi in zip(acuVerifyTimingLst, normalizeIterationsLst)]
fdiv4 = [float(ai)/bi for ai,bi in zip(merkleVerifyTimingLst, normalizeIterationsLst)]

print (sizes)
print ("Initializing Data Structure")
print (acuLstTiming)
print (merkleLstTiming)
print(acuLstBatchTiming)
print ("Create a Single Evidence")
print(fdiv1)
print(fdiv2)
print ("Create Evidences")
print(acuEvidenceTimingLst)
print(merkleEvidenceTimingLst)
print ("Verify a Single Evidence")
print(fdiv3)
print(fdiv4)

createGraph(sizes, acuLstTiming, merkleLstTiming,"Initializing Data Structure")
createGraph(sizes, acuLstBatchTiming, merkleLstTiming,"Initializing Data Structure (with Batch)")
createGraph(sizes, fdiv1,fdiv2,"Create a Single Evidence")
createGraph(sizes, acuEvidenceTimingLst,merkleEvidenceTimingLst,"Create Evidences")
createGraph(sizes, fdiv3,fdiv4,"Verify a Single Evidence")




