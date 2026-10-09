// Disposable TVM fixture only; deliberately target pre-London EVM opcodes.
const fs = require('node:fs');
const solc = require('../evm/node_modules/solc');
const source = fs.readFileSync(__dirname + '/../evm/AcceptanceToken.sol', 'utf8');
const input = { language: 'Solidity', sources: { 'AcceptanceToken.sol': { content: source } }, settings: { evmVersion: 'petersburg', outputSelection: { '*': { '*': ['evm.bytecode.object', 'abi'] } } } };
const output = JSON.parse(solc.compile(JSON.stringify(input)));
if ((output.errors || []).some(e => e.severity === 'error')) throw new Error('TVM fixture compilation failed');
const contract = output.contracts['AcceptanceToken.sol'].AcceptanceToken;
fs.writeFileSync(process.argv[2], JSON.stringify({ bytecode: contract.evm.bytecode.object, abi: contract.abi }));
