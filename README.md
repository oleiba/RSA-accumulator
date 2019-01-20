# RSA-accumulator
Cryptographic accumulator based on the strong RSA assumption.<br>
Generating and verifying proofs in Python, verifier in Solidity.

### Prerequesites

* Python3 
* Node.js 10.14.0, NPM

### Testing

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

[1] https://github.com/Tierion/pymerkletools <br> 
[2] https://github.com/ameensol/merkle-tree-solidity


