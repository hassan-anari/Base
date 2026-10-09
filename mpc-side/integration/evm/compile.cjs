const fs = require('node:fs');
const solc = require('solc');
const input = { language: 'Solidity', sources: { 'AcceptanceToken.sol': { content: fs.readFileSync(__dirname + '/AcceptanceToken.sol', 'utf8') } }, settings: { evmVersion: 'shanghai', outputSelection: { '*': { '*': ['evm.bytecode.object'] } } } };
const output = JSON.parse(solc.compile(JSON.stringify(input)));
if ((output.errors || []).some(e => e.severity === 'error')) throw new Error('acceptance token compilation failed');
fs.writeFileSync(process.argv[2], output.contracts['AcceptanceToken.sol'].AcceptanceToken.evm.bytecode.object);
