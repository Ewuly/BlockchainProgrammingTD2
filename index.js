const crypto = require('crypto');

function generateRandomInt() { 
    const randomBytes = crypto.randomBytes(16); // Generate 16 bytes (128 bits)
    
    // Convert the randomBytes to binary representation
    const binaryRepresentation = randomBytes.reduce((acc, byte) => {
        return acc + byte.toString(2).padStart(8, '0');
    }, '');
    
    // Convert the randomBytes to hexadecimal representation
    const hexRepresentation = randomBytes.toString('hex');

    return {
        binary: binaryRepresentation,
        bytes: Array.from(randomBytes),
        hex: hexRepresentation
    };
}
// 1. Generate a random integer that can serve as a safe seed for a wallet
const randomSeed = generateRandomInt();
// 2.1 Represent this seed in binary/bytes/hex
console.log('Random Seed Binary:', randomSeed.binary);
console.log('Random Seed Bytes:', randomSeed.bytes);
console.log('Random Seed Hex:', randomSeed.hex);



const entropy = randomSeed.binary;

//Create checksum
const size = Math.floor(entropy.length / 32); // number of bits to take from hash of entropy (1 bit checksum for every 32 bits entropy)
const sha256 = crypto.createHash('sha256').update(entropy).digest(); // hash of entropy (in raw binary)
const sha256Hex = sha256.toString('hex'); // Convert buffer to hexadecimal string representation
function hexToBinary(hex) {
    let binary = "";
    for (let i = 0; i < hex.length; i++) {
      const decimal = parseInt(hex[i], 16);
      const bin = decimal.toString(2).padStart(4, "0");
      binary += bin;
    }
    return binary;
  }
const sha256Binary = hexToBinary(sha256Hex);
const checksum = sha256Binary.slice(0, size).toString('binary'); // get desired number of bits
//Combine
const full = entropy + checksum;
console.log(`combined: ${full}`);

// 2.2 Divide it into lots of 11 bits 
const pieces = full.match(/.{1,11}/g);

//3.1 Assign a word to each lot according to the BIP 39 list
//Get the word list as an array
var fs = require("fs");
var text = fs.readFileSync("C:/Users/auria/Downloads/english.txt").toString();
const wordList = text.split("\n")
//Convert groups of bits to array of words
console.log("words:");
const sentence = [];
pieces.forEach(piece => {
  const i = parseInt(piece, 2); // convert string of 11 bits to an integer
  const word = wordList[i]; // get the corresponding word from wordlist
  sentence.push(word);
  console.log(`${piece} ${i.toString().padStart(4)} ${word}`);
});

//3.2 display the seed in mnemonic form
const mnemonic = sentence.join(" ");
console.log(`mnemonic: ${mnemonic}`); //=> "punch shock entire north file identify"


//4. Allow the import of a mnemonic seed 
//const mnemonic=seed to import
const passphrase = ''; // Passphrase (can be empty)

const salt = `mnemonic${passphrase}`;
const iterations = 2048;
const keylength = 64;
const digest = 'sha512';

const resultBuffer = crypto.pbkdf2Sync(mnemonic, salt, iterations, keylength, digest);
const seed = resultBuffer.toString('hex');
console.log('Seed: ', seed);



//1. Extract the master private key and the chain code
const hmac = crypto.createHmac('sha512', Buffer.from('Bitcoin seed'));
hmac.update(seed);

const hmacResult = hmac.digest();
const masterPrivateKey = hmacResult.slice(0, 32).toString('hex');
const chainCode = hmacResult.slice(32).toString('hex');

console.log('Master Private Key:', masterPrivateKey);
console.log('Chain Code:', chainCode);


//2. Extract the master public key
const elliptic = require('elliptic');
const curve = elliptic.curves['secp256k1'];
const ec = new elliptic.ec(curve);

const masterPrivateKeyBuffer = Buffer.from(masterPrivateKey, 'hex');
const chainCodeBuffer = Buffer.from(chainCode, 'hex');
// Calculate the master public key
const masterPublicKeyPoint = ec.g.mul(masterPrivateKeyBuffer).add(ec.g.mul(chainCodeBuffer));
const masterPublicKeyBuffer = Buffer.from(masterPublicKeyPoint.encodeCompressed());
console.log('Master Public Key:', masterPublicKeyBuffer.toString('hex'));


//3. Generate a child key
const childPrivateKeyBuffer = Buffer.alloc(32, 0);
for (let i = 0; i < 32; i++) {
  childPrivateKeyBuffer[i] = masterPrivateKeyBuffer[i] ^ chainCodeBuffer[i];
}
// Ensure it's a valid private key (perform modulo operation)
const curveOrder = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex'); //This hexadecimal represents the curve order for secp256k1
const childPrivateKey = BigInt(`0x${childPrivateKeyBuffer.toString('hex')}`);
const validChildPrivateKey = childPrivateKey % BigInt(`0x${curveOrder.toString('hex')}`);
const childPublicKeyPoint = ec.g.mul(validChildPrivateKey);
const childPublicKeyBuffer = Buffer.from(childPublicKeyPoint.encodeCompressed());

console.log('Child Private Key:', validChildPrivateKey.toString(16));
console.log('Child Public Key:', childPublicKeyBuffer.toString('hex'));


//4. Generate a child key at index N
// Index for the child key (e.g., N=1)
const indexN = 10;
const data = Buffer.concat([Buffer.alloc(1, 0), masterPrivateKeyBuffer, Buffer.alloc(32, 0), Buffer.from(indexN.toString(16), 'hex')]);

// Use HMAC-SHA512 to derive a child private key and chain code
const hmac2 = crypto.createHmac('sha512', chainCodeBuffer);
hmac2.update(data);
const hmacResult2 = hmac2.digest();
// Process the hex string in chunks and calculate the child private key
const hexString = hmacResult2.slice(0, 32).toString('hex');
let childPrivateKeyN = BigInt(0);
for (let i = 0; i < hexString.length; i += 15) {
  const chunk = hexString.slice(i, i + 15);
  const chunkBigInt = BigInt(`0x${chunk}`);
  childPrivateKeyN = (childPrivateKeyN * BigInt(2 ** (chunk.length * 4))) + chunkBigInt;
}
// Calculate modulo
const curveOrderBigInt = BigInt('0x' + curveOrder.toString('hex'));
childPrivateKeyN %= curveOrderBigInt;
// Derive the child public key
const childPublicKeyPointN = ec.g.mul(childPrivateKeyN).add(ec.g.mul(chainCodeBuffer));
const childPublicKeyBufferN = Buffer.from(childPublicKeyPointN.encodeCompressed());

console.log(`Child Private Key N=${indexN}:`, childPrivateKeyN.toString(16));
console.log(`Child Public Key N=${indexN}:`, childPublicKeyBufferN.toString('hex'));
