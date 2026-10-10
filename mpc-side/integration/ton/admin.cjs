// Isolated fixture administrator only; never a custody signer. Keys stay in memory.
const {WalletContractV5R1}=require('@ton/ton');
const {Cell,Address,beginCell,contractAddress,internal,storeMessage,external}=require('@ton/core');
const {keyPairFromSeed}=require('@ton/crypto');
const crypto=require('crypto'),fs=require('fs'),path=require('path'),readline=require('readline');
const keys=keyPairFromSeed(crypto.randomBytes(32));
const wallet=WalletContractV5R1.create({publicKey:keys.publicKey,walletId:{networkGlobalId:-777,context:{workchain:0,walletVersion:'v5r1',subwalletNumber:0}}});
const artifact=n=>Cell.fromBoc(Buffer.from(fs.readFileSync(path.join(__dirname,'../../../backend-side/custody/ton_contracts/'+n+'.boc.hex'),'utf8').trim(),'hex'))[0];
const content=beginCell().storeUint(1,8).storeStringTail('https://invalid.local/isolated-fixture-only').endCell();
const masterInit={code:artifact('jetton-minter'),data:beginCell().storeCoins(0).storeAddress(wallet.address).storeRef(content).storeRef(artifact('jetton-wallet')).endCell()};
const master=contractAddress(0,masterInit);
function command(q){
 if(q.action==='identity')return {admin:wallet.address.toRawString(),master:master.toRawString(),content_hash:content.hash().toString('hex')};
 let msg;
 if(q.action==='deploy')msg=internal({to:master,value:1000000000n,bounce:false,init:masterInit});
 if(q.action==='mint'){
  const transfer=beginCell().storeUint(0x178d4519,32).storeUint(q.query||1,64).storeCoins(BigInt(q.amount)).storeAddress(master).storeAddress(wallet.address).storeCoins(0).storeBit(0).endCell();
  msg=internal({to:master,value:500000000n,bounce:true,body:beginCell().storeUint(21,32).storeUint(q.query||1,64).storeAddress(Address.parse(q.owner)).storeCoins(200000000n).storeRef(transfer).endCell()});
 }
 if(q.action==='native')msg=internal({to:Address.parse(q.owner),value:BigInt(q.amount),bounce:false,body:beginCell().storeUint(0,32).storeStringTail(q.memo||'').endCell()});
 if(q.action==='jetton'){
  const jwCode=artifact('jetton-wallet');
  const jw=contractAddress(0,{code:jwCode,data:beginCell().storeCoins(0).storeAddress(wallet.address).storeAddress(master).storeRef(jwCode).endCell()});
  msg=internal({to:jw,value:100000000n,bounce:true,body:beginCell().storeUint(0x0f8a7ea5,32).storeUint(q.query||200,64).storeCoins(BigInt(q.amount)).storeAddress(Address.parse(q.owner)).storeAddress(wallet.address).storeBit(0).storeCoins(1).storeBit(1).storeRef(beginCell().storeUint(0,32).storeStringTail(q.memo||'').endCell()).endCell()});
 }
 if(!msg)throw Error('fixture action unsupported');
 const body=wallet.createTransfer({seqno:q.seqno,timeout:q.valid_until,sendMode:3,messages:[msg],secretKey:keys.secretKey});
 const wire=beginCell().store(storeMessage(external({to:wallet.address,init:q.seqno===0?wallet.init:undefined,body}))).endCell();
 return {boc:wire.toBoc({idx:false,crc32:false}).toString('hex'),hash:wire.hash().toString('hex')};
}
(async()=>{for await(const line of readline.createInterface({input:process.stdin})){try{process.stdout.write(JSON.stringify({result:command(JSON.parse(line))})+'\n');}catch(e){process.stdout.write(JSON.stringify({error:e.stack})+'\n');}}})();
