const prompt = require("syncprompt");
const crypto = require("crypto");
var fs = require('fs');
const HmacSHA512 = require('crypto-js/hmac-sha512');
const enc = require('crypto-js/enc-hex');
const secp256k1 = require('secp256k1');
const pbkdf2 = require('pbkdf2');

prompt("We weill create a mnemonic for you, press enter to continue...");

const buf = crypto.randomBytes(32); // generate cryptographicly secure random bytes 

const num = BigInt('0x' + buf.toString("hex")); // convert these bytes into an int

// function to convert int into 
function int_to_bits_array(nb, size) {
    var ar = [];
    for (var i = BigInt(0); i < size; i++)
        ar[i] = (nb >> i) & BigInt(1);
    
    return ar;
}

var bits_array = int_to_bits_array(num, 128); // Convert number into array of bits

var hash = crypto.createHash('sha256'); // create a sha256 hash object

hash.update(buf); // hash the number to create a 256 bits seed

const hash_last_4 = int_to_bits_array(BigInt(hash.digest()[0]), 4) //create bits array from 4 last digits of hash

const entropy = bits_array.concat(hash_last_4); // concatenate the 4 bytes

console.log("entropy:", entropy);
console.log("entropy length:", entropy.length);

// loads bip39 txt file
var bip39txt;
try {  
    var data = fs.readFileSync('bip39.txt', 'utf8');
    bip39txt = data.toString();
} catch(e) {
    console.log('Error:', e.stack);
}

// Create array from bip39 string 
const bip39arr = bip39txt.split("\n").slice(0, bip39txt.split("\n").length - 1); // split then eject the last element as it's jsut an empty string

// create our own mnemonic based on the entropy
function bits_to_mnemonic_word(bits){ //transforms a 11 bits binary into a mnemonic string
    var index = BigInt(0);
    for (var i = BigInt(0); i < bits.length; i++){
        index += bits[i] * BigInt(2)**(BigInt(bits.length) - i - BigInt(1));
    }
    return bip39arr[index];
}

// create an array of bits from mnemonic
function mnemonic_word_to_bits(word) {
    var bits = [];
    var index = bip39arr.indexOf(word);
    for (var i = 10; i >= 0; i--){
        if (index >= 2**i) {
            index -= 2**i;
            bits.push(1);
        }else{
            bits.push(0);
        }
    }
    return bits;
}

// from array of bits to hex string
function bits_to_hex(bits){
    if (bits.length%4 != 0){
        throw Error("bits array invalid");
    }
    const hex_arr = ["a", "b", "c", "d", "e", "f"];
    var result = "";
    for (var i = BigInt(0); i < bits.length; i+=BigInt(4)){
        var sum = BigInt(0);
        for (var j = i; j < i+BigInt(4); j++){
            sum += bits[j]*BigInt(2)**(BigInt(4)-(j - i)-BigInt(1));
        }
        //console.log(bits.slice(i, i+4), sum);
        if (sum >= 10){
            result += hex_arr[sum - BigInt(10)];
        }else{
            result += sum.toString();
        }
    }
    return result;
}

// create mnemonic from entropy
const mnemonic_entropy = [];
for (var i = 0; i < 12; i++){
    mnemonic_entropy.push(bits_to_mnemonic_word(entropy.slice(i*11, (i+1)*11)));
}

console.log("\nVoici votre entropy mnemonic:", mnemonic_entropy.join(" "));
console.log("Voici votre entropy hex", bits_to_hex(entropy));

// function to validate a string as a mnemonic format
function valid_mnemonic(mnemonic){
    var r = true;
    if (mnemonic.split(" ").length != 12){
        console.log(mnemonic, "is invalid");
        return false;
    }
    for (var i = 0; i < mnemonic.split(" ").length; i++) {
        if (!bip39arr.includes(mnemonic.split(" ")[i])) {
            console.log(mnemonic, "is not a part of bip39");
            r = false;
        }
        // if valid
        if (i === mnemonic.split(" ").length - 1 && r === true){
            return true;
        }
    };
}

// ask user to import mnemonic
let imported_mnemonic = prompt("\nPlease import a mnemonic of your choice.\n");

// if entered mnemonic is valid
while (!valid_mnemonic(imported_mnemonic)){
    imported_mnemonic = prompt("\nError, please enter a valid mnemonic.\n");
}

prompt("\n\nSuccessfuly imported mnemonic, press enter to continue...");

// create bits array seed from mnemonic (not )
var imported_mnemonic_bits = [];
imported_mnemonic.split(" ").forEach((word) => {
    imported_mnemonic_bits = imported_mnemonic_bits.concat(mnemonic_word_to_bits(word));
});

// Calculate BPKDF2 function from mnemonic
function PBKDF2(mnemonic){
    var signed = mnemonic;
    var hmac = crypto.createHmac("sha512", "mnemonic");
    signed = hmac.update(Buffer.from(signed, "utf-8")).digest('hex');
    for (var i = 0; i < 2047; i++){
        var hmac = crypto.createHmac("sha512", "mnemonic");
        signed = hmac.update(Buffer.from(signed, "hex")).digest('hex');
    }
    return signed;
}

// get the root_seed as a buffer (binary) format
var root_seed = pbkdf2.pbkdf2Sync(imported_mnemonic, 'mnemonic', 2048, 64, 'sha512');

// seed as hex format
console.log("\nseed:", root_seed.toString('hex'));

// hmach sha512 of seed
var hmac = crypto.createHmac("sha512", "Bitcoin seed");
var hashed_root_seed = hmac.update(root_seed).digest();

// See Serialization format in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
function serializePrvKey(chain_code_hex, prv_key_hex) {
    key = "0488ADE4" + "00" + "00000000" + "00000000" + chain_code_hex + prv_key_hex;
}

// master private key and chain code
var master_private_key = hashed_root_seed.toString("hex").slice(0, 64);
var master_chain_code = hashed_root_seed.toString("hex").slice(64);

console.log("\nmaster private key:", master_private_key);
console.log("master chain code:", master_chain_code);

// master public key from EC secp256k1
const master_public_key = secp256k1.publicKeyCreate(Buffer.from(master_private_key, "hex"));

console.log("master public key:", Buffer.from(master_public_key).toString('hex'));

// Function to generate child private key, child public key and child chain code
function generatingChild(parentPrivateKey, parentPublicKey, parentChainCode,index,type) {
    var parentPrivate = parentPrivateKey.length === 64 ? parentPrivateKey : '0'.repeat(64-parentPrivateKey.length)+parentPrivateKey;
    const keyToUse = type === 'private' ? '00'+parentPrivate : parentPublicKey; //Use private key if hardened-index else public key
    const hmacHash = HmacSHA512(enc.parse(keyToUse+index),enc.parse(parentChainCode)).toString();
    const [leftBits,childChainCode] = separateKeyChain(hmacHash);
    const N = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'; //As defined in secp256k1 ecc
    var childPrivateKey = (BigInt('0x'+parentPrivate) + BigInt('0x'+leftBits)) % BigInt(N);
    childPrivateKey = childPrivateKey.toString(16); //Converting from decimal to hex
    const childPublicKey = Buffer.from(secp256k1.publicKeyCreate(Buffer.from(childPrivateKey, "hex"))).toString("hex"); //Using ECC function taken from 'ecc.js' file

    return [childPrivateKey,childPublicKey,childChainCode];
};

//Function to be used in generatingChild function to separate hash into private key and chain code
function separateKeyChain(hmacHash) {
    const privateKeyPart = hmacHash.substr(0,64);
    const chainCodePart = hmacHash.substr(64,64);
    return [privateKeyPart,chainCodePart];
}

// Function to derive a private key following a path (m/0/../0)
function derive_path(prv_key, pub_key, chain_code, path){
    if (path[0] == "m"){
        path = path.slice(2);
    }
    if (path[path.length-1] == "/"){
        path = path.slice(0, path.length-1);
    }

    var index = path.split("/")[0];
    var child_prv_key;
    var child_pub_key;
    var child_chain_code;

    if (index[index.length - 1] == "'"){
        //hardened
        index = (Math.pow(2, 31) + parseInt(index.split("'")[0])).toString(16);
        index = index.length === 8 ? index : '0'.repeat(8-index.length)+index;
        [child_prv_key, child_pub_key, child_chain_code] = generatingChild(prv_key, pub_key, chain_code, index, 'private')
        if (path.split("/").length > 1){
            return derive_path(child_prv_key, child_pub_key, child_chain_code, path.split("/").slice(1).join("/"))
        }
    }
    else {
        //not hardened
        index = (parseInt(index.split("'")[0])).toString(16);
        index = index.length === 8 ? index : '0'.repeat(8-index.length)+index;
        [child_prv_key, child_pub_key, child_chain_code] = generatingChild(prv_key, pub_key, chain_code, index, 'public')
        if (path.split("/").length > 1){
            return derive_path(child_prv_key, child_pub_key, child_chain_code, path.split("/").slice(1).join("/"))
        }
    }
    return [child_prv_key, child_pub_key, child_chain_code];
}

// Check if path is correct
function valid_path(path){
    let regex = /^m+\/+([0-9]{1,10}[']?[\/])*[0-9]{1,10}[']?$/;
    if (path.match(regex) === null){
        return false;
    }else{
        return true;
    }
}

// ask user to input a path
let path = prompt("Please enter a path to derive the desired wallet.\nMake sure to respect the standard format (example: m/44'/0'/0'/0/1)\n")

while (!valid_path(path)){
    path = prompt("Error, please enter a valid path (example: m/44'/0'/0'/0/1)\n")
}

let derived_prv_key;
let derived_pub_key;
let derived_chain_code;

// derive path
[derived_prv_key, derived_pub_key, derived_chain_code] = derive_path(master_private_key, master_public_key, master_chain_code, path);

console.log("\nHere is your wallet following the path", path, "\nDerived private key:", derived_prv_key, "\nDerived public key", derived_pub_key, "\nDerived chain code", derived_chain_code);