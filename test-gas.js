const fs = require('fs')
const solc = require('solc')
const async = require('async')
const MerkleTree = require('merkle-tree-solidity')
const keccak256 = require('ethereumjs-util').keccak256
const Web3 = require('web3')
const path = require('path')
const jsonfile = require('jsonfile')
const web3 = new Web3()
const debug = require('debug')('test-gas')
const ethereumJs = require('ethereumjs-util')
const EthereumTx = require('ethereumjs-tx')
const web3Povider = 'wss://ropsten.infura.io/ws'
const chainId = 3   // Ropsten
const argv = require('yargs').argv
const spawn = require("child_process").spawn

// hardcoded private key for Ropsten
const privateKey = Buffer.from(argv.privateKey || 'aa2f4955b46b2a8a104d01f7df7a610fb8a929a8b35da9c23ebaffeaf687cdb6', 'hex')
const from = ethereumJs.privateToAddress(privateKey).toString('hex')
web3.setProvider(new Web3.providers.WebsocketProvider(web3Povider))

const MERKLE_PROOF_CONTRACT_PATH = path.join(__dirname, 'contracts/MerkleProof.sol')
const MERKLE_PROOF_RESULTS_PATH = path.join(__dirname, 'generated/merkle-gas-results.json')

const ACCUMULATOR_CONTRACT_PATH = path.join(__dirname, 'contracts/RSAAccumulator.sol')
const BYTES_LIB_CONTRACT_PATH = path.join(__dirname, 'contracts/BytesLib.sol')
const ACCUMULATOR_PROOF_RESULT_PATH = path.join(__dirname, 'generated/acc-gas-results.json')

async function testMerkleProofGas (setSizes) {
    let compiledContract = await compileContract([MERKLE_PROOF_CONTRACT_PATH])
    let contractObj = new web3.eth.Contract(compiledContract.abi)
    try {
        // deploy contract
        const deploy = contractObj.deploy({data: '0x' + compiledContract.bytecode})
        let receipt = await sendTransaction(deploy)
        const contractAddress = receipt.contractAddress

        await executeMerkleProofEstimations(setSizes, contractObj, contractAddress)
    } catch (e) {
        console.error(e)
    }
}

function testAccumulatorGas () {
    return new Promise((resolve, reject) => {
        const pythonProcess = spawn('python3',["generate-proof.py"])
        pythonProcess.stdout.on('data', async (data) => {
            // Do something with the data returned from python script
            const returnValues = data.toString().split(',')
                .map(s => s.replace(/^\s+|\s+$/g, ''))  // remove line breaks if any
            const modulus = returnValues[0]
            const accumulatorPre = returnValues[1]
            const element = returnValues[2]
            const accumulatorPost = returnValues[3]
            let compiledContract = await compileContract([ACCUMULATOR_CONTRACT_PATH, BYTES_LIB_CONTRACT_PATH])
            let contractObj = new web3.eth.Contract(compiledContract.abi)
            try {
                // deploy contract
                var deployObj = {
                    data: '0x' + compiledContract.bytecode,
                    arguments: [modulus, accumulatorPost]
                }
                const deploy = contractObj.deploy(deployObj)
                let receipt = await sendTransaction(deploy)
                const contractAddress = receipt.contractAddress

                await executeAccumulatorEstimation(accumulatorPre, element, contractObj, contractAddress)
                resolve()
            } catch (e) {
                console.error(e)
                reject(e)
            }
        })
    })
}

async function executeMerkleProofEstimations (setSizes,  contractObj, contractAddress) {
    let results = {}
    await Promise.all(setSizes.map(async (setSize) => {
        const elementIndex = 0
        const proofObj = generateProof(setSize, elementIndex)
        let method = contractObj.methods.checkProofOrdered(proofObj.proof, proofObj.root, proofObj.element, elementIndex + 1)
        let gas = await sendTransaction(method, true, contractAddress)
        results[setSize] = gas
        debug(`results[${setSize}] = ${gas}`)
    }))
    jsonfile.writeFileSync(MERKLE_PROOF_RESULTS_PATH, results)
}

async function executeAccumulatorEstimation (accumulatorPre, element, contractObj, contractAddress) {
    let method = contractObj.methods.verify(accumulatorPre, element)
    let gas = await sendTransaction(method, true, contractAddress)
    fs.writeFileSync(ACCUMULATOR_PROOF_RESULT_PATH, gas)
}

async function sendTransaction (method, estimateOnly, to) {
    var data = method.encodeABI()
    try {
        let nonce = await web3.eth.getTransactionCount(from)
        let gasLimit = await web3.eth.estimateGas({from, to, data})
        debug('gasLimit = %s', gasLimit)
        if (estimateOnly) {
            return gasLimit
        }
        let gasPrice = await web3.eth.getGasPrice()
        gasPrice = parseInt(gasPrice)
        debug('gasPrice = %s', gasPrice)
        let balance = await web3.eth.getBalance(from)
        debug('balance = %s', balance)
        let txParams = {
            value: 0,
            to,
            nonce,
            gasLimit,
            gasPrice,
            data,
            chainId
        }
        debug('txParams = %j', txParams)
        let tx = new EthereumTx(txParams)
        debug('created tx')
        tx.sign(privateKey)
        debug('signed tx')
        let senderAdderss = tx.getSenderAddress()
        debug('senderAdderss = %s', senderAdderss.toString('hex'))
        let serializedTx = '0x' + tx.serialize().toString('hex')
        debug('serializedTx = %s', serializedTx)
        let receipt = await web3.eth.sendSignedTransaction(serializedTx)
        return receipt
    } catch (err) {
        console.error(err)
    }
}

async function compileContract (contractSources) {
    const input = {
        sources: {},
        language: 'Solidity',
        settings: {
            outputSelection: {
                '*': {
                    '*': ['*']
                }
            }
        }
    }
    contractSources.forEach(s => {
        const fileName = path.basename(s)
        input.sources[fileName] = {content: fs.readFileSync(s, 'utf8')}
    })
    debug('solc.version() = ', solc.version())
    debug('contractSources =', contractSources)
    let contractCompiled = await solc.compile(JSON.stringify(input))
    contractCompiledJson = JSON.parse(contractCompiled)
    const fileName = path.basename(contractSources[0])
    let contractObj = contractCompiledJson.contracts[fileName][fileName.substr(0, fileName.length - '.sol'.length)]
    let bytecode = contractObj.evm.bytecode.object
    let abi = contractObj.abi
    let json = {abi, bytecode}
    return json
}

function generateProof(numOfElements, elementIndex) {
    let elements = []
    for (let i = 0; i < numOfElements; i++) {
        elements.push(keccak256(i))
    }

    const merkleTree = MerkleTree.default(elements, true)
    const rootBuf = merkleTree.getRoot()
    const root = '0x' + rootBuf.toString('hex')
    const elementBuf = elements[elementIndex]
    const element = '0x' + elementBuf.toString('hex')

    const proofBufArray = merkleTree.getProofOrdered(elementBuf, elementIndex + 1)
    const proof = '0x' + proofBufArray.map(e => e.toString('hex')).join('')

    return {root, element, proof}
}

// hard-coded private key. This is very very BAD! Use this method only for Testnet!

let setSizes = []
for (let i = 0; i < 21; i++) {
    setSizes.push(Math.pow(2, i))
}

async function start() {
    await testMerkleProofGas(setSizes)
    console.log('Done - Merkle proof gas, written result to', MERKLE_PROOF_RESULTS_PATH)
    await testAccumulatorGas()
    console.log('Done - RSA accumulator gas, written result to', ACCUMULATOR_PROOF_RESULT_PATH)
    return
}

start()