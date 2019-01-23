# RSA-accumulator

Cryptographic accumulator based on the strong RSA assumption [Bd94, BP97, CL02, BBF18].<br>
Generating and verifying proofs in Python, verifier in Solidity.<br>

### Prerequesites

* Python3 
* Node.js 10.14.0, NPM

### Unit testing

`$ python3 -m unittest test`

### Benchmarks

* Compare performance (compared with Python Merkle Tree [1]):
```
$ python3 test-performance.py
```

* Compare gas results (compared with Merkle Proof verifier [2]) :
```
$ npm install
$ node test-gas.js
```

The tests above generate relevant data files at the `generated` directory.

[1] https://github.com/Tierion/pymerkletools <br> 
[2] https://github.com/ameensol/merkle-tree-solidity

### References

[Bd94] [One-way accumulators: A decentralized
alternative to digital sinatures](https://link.springer.com/content/pdf/10.1007/3-540-48285-7_24.pdf), Josh Cohen Benaloh and Michael de Mare.<br> 
[BP97] [Collision-free accumulators and fail-stop signature
schemes without trees](https://link.springer.com/content/pdf/10.1007/3-540-69053-0_33.pdf), Niko Bari and Birgit Pfitzmann. <br>
[CL02] [Dynamic accumulators and application to
efficient revocation of anonymous credentials](https://link.springer.com/content/pdf/10.1007/3-540-45708-9_5.pdf), Jan Camenisch and Anna Lysyanskaya. <br>
[BBF18] [Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains](https://eprint.iacr.org/2018/1188.pdf), Dan Boneh, Benedikt Bünz, Benjamin Fisch.<br>
