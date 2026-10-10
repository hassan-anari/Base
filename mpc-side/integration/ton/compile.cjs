// Recompile pinned TEP-74 sources and compare their exact approved code hashes.
const {compileFunc}=require('@ton-community/func-js');
const {compileFunc:compileV5}=require('@ton-community/func-js-v5');
const {Cell}=require('@ton/core');
const fs=require('fs'),path=require('path'),assert=require('assert');
(async()=>{
 const v5=await compileV5({targets:['wallet_v5.fc'],sources:p=>fs.readFileSync(path.join(__dirname,'contracts/v5',p),'utf8')});
 assert.equal(v5.status,'ok',v5.message);
 const wallet=Cell.fromBoc(Buffer.from(v5.codeBoc,'base64'))[0];
 assert.equal(wallet.hash().toString('hex'),'20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f');
 console.log('wallet-v5r1 '+wallet.hash().toString('hex'));
 for(const [name,hash] of [['jetton-wallet','a760d629d5343e76d045017d9dc216fc8a307a8377815feb2b0a5c490e733486'],['jetton-minter','f95ba0330b38cdf3459b1e811e5fc6fa6cfee566d7b764455c0468140365a737']]){
  const r=await compileFunc({targets:['stdlib.fc','op-codes.fc','params.fc','jetton-utils.fc',name+'.fc'],sources:p=>fs.readFileSync(path.join(__dirname,'contracts',p),'utf8')});
  assert.equal(r.status,'ok',r.message);
  const code=Cell.fromBoc(Buffer.from(r.codeBoc,'base64'))[0];assert.equal(code.hash().toString('hex'),hash);
  console.log(name+' '+hash);
 }
})().catch(e=>{console.error(e);process.exit(1)});
