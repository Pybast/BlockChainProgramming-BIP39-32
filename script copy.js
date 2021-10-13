const prompt = require("prompt-sync")();
const crypto = require("crypto");
var fs = require('fs');
const HmacSHA512 = require('crypto-js/hmac-sha512');
const enc = require('crypto-js/enc-hex');

// input = prompt("Enter random key strokes");

const buf = crypto.randomBytes(128);

const num = buf.readInt32BE();

function int_to_bits_array(nb, size) {
    var ar = [];
    for (var i = 0; i < size; i++)
        ar[i] = (nb >> i) & 1;
    
    return ar;
}

function bits_array_to_int(barr, size){
    
}

// console.log("random int", num);
var bits_array = int_to_bits_array(num, 128);
// console.log("conversion to bits array", bits_array);

var hash = crypto.createHash('sha256');

hash.update(buf);

const hash_last_4 = int_to_bits_array(hash.digest()[0], 4)

const entropy = bits_array.concat(hash_last_4);

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

const bip39arr = bip39txt.split("\n").slice(0, bip39txt.split("\n").length - 1); // split then eject the last element as it's jsut an empty string

// console.log(bip39arr.length);

// create our own mnemonic based on the entropy

function bits_to_mnemonic_word(bits){ //transforms a 11 bits binary into a mnemonic string
    // console.log(bits);
    var index = 0;
    for (var i = 0; i < bits.length; i++){
        index += bits[i] * 2**(bits.length - i - 1);
    }
    // console.log(bip39arr[index]);
    return bip39arr[index];
}

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

function bits_to_hex(bits){
    if (bits.length%4 != 0){
        throw Error("bits array invalid");
    }
    const hex_arr = ["a", "b", "c", "d", "e", "f"];
    var result = "";
    for (var i = 0; i < bits.length; i+=4){
        var sum = 0;
        for (var j = i; j < i+4; j++){
            sum += bits[j]*2**(4-(j - i)-1);
        }
        //console.log(bits.slice(i, i+4), sum);
        if (sum >= 10){
            result += hex_arr[sum - 10];
        }else{
            result += sum.toString();
        }
    }
    return result;
}

const mnemonic_entropy = [];

for (var i = 0; i < 12; i++){
    mnemonic_entropy.push(bits_to_mnemonic_word(entropy.slice(i*11, (i+1)*11)));
}

console.log("\nVoici votre entropy mnemonic:\n" + mnemonic_entropy.join(" "));

console.log("\nVoici votre entropy hex", bits_to_hex(entropy));

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

var imported_mnemonic = "mushroom orange black valve erase brother submit biology tortoise debate arrive slim"; //prompt("\nMerci d'importer une mnemonic.\n");

// if entered mnemonic is valid
while (!valid_mnemonic(imported_mnemonic)){
    imported_mnemonic = prompt("Erreur, merci d'importer une autre mnemonic.");
}

var imported_mnemonic_bits = [];

imported_mnemonic.split(" ").forEach((word) => {
    imported_mnemonic_bits = imported_mnemonic_bits.concat(mnemonic_word_to_bits(word));
});

// console.log(imported_mnemonic_bits);

// console.log(bits_to_hex(imported_mnemonic_bits).length, " -> ", bits_to_hex(imported_mnemonic_bits));

// Derivation de la seed

const pbkdf2 = require('pbkdf2');
const bs58 = require('bs58');

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

var root_seed = pbkdf2.pbkdf2Sync(imported_mnemonic, 'mnemonic', 2048, 64, 'sha512');

console.log("\nseed:", root_seed.toString('hex'));

var hmac = crypto.createHmac("sha512", "Bitcoin seed");
var hashed_root_seed = hmac.update(root_seed).digest();

// console.log(bs58.encode(Buffer.from("0488ADE4" + hashed_root_seed.toString("hex") + "bbb", "hex")));
// console.log(bs58.encode(Buffer.from("0488ADE4" + hashed_root_seed.toString("hex"), "hex")).length);

// See Serialization format in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
function serializePrvKey(chain_code_hex, prv_key_hex) {
    key = "0488ADE4" + "00" + "00000000" + "00000000" + chain_code_hex + prv_key_hex;
}

//console.log(serializePrvKey(hashed_root_seed.toString("hex")));

var master_private_key = hashed_root_seed.toString("hex").slice(0, 64);
var master_chain_code = hashed_root_seed.toString("hex").slice(64);

console.log("\nmaster private key:", master_private_key);
console.log("master chain code:", master_chain_code);

const secp256k1 = require('secp256k1');

const master_public_key = secp256k1.publicKeyCreate(Buffer.from(master_private_key, "hex"));

console.log("master public key:", Buffer.from(master_public_key).toString('hex'));

// const derived_extended_prv_key = derive_prv_key("00", master_private_key, master_chain_code, "8000002c");
// const derived_prv_key = derived_extended_prv_key.toString("hex").slice(0, 64);
// const derived_chain_code = derived_extended_prv_key.toString('hex').slice(64);
// const derived_pub_key = Buffer.from(secp256k1.publicKeyCreate(Buffer.from(derived_prv_key, 'hex'))).toString('hex');
// console.log("\n45th hardened private key", derived_prv_key);
// console.log("45th hardened public key", derived_pub_key);

// console.log(derive_path(master_private_key, master_chain_code, "m/45'"));


//Function to generate child private key, child public key and child chain code
function generatingChild(parentPrivateKey, parentPublicKey, parentChainCode,index,type) {
    let parentPrivate = parentPrivateKey.length === 64 ? parentPrivateKey : '0'.repeat(64-parentPrivateKey.length)+parentPrivateKey;
    const keyToUse = type === 'private' ? '00'+parentPrivate : parentPublicKey; //Use private key if hardened-index else public key
    const hmacHash = HmacSHA512(enc.parse(keyToUse+index),enc.parse(parentChainCode)).toString();
    const [leftBits,childChainCode] = separateKeyChain(hmacHash);
    const N = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'; //As defined in secp256k1 ecc
    let childPrivateKey = (BigInt('0x'+parentPrivate) + BigInt('0x'+leftBits)) % BigInt(N);
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

var child = generatingChild(master_private_key, master_public_key, master_chain_code, (Math.pow(2, 31) + 44).toString(16), 'private');
console.log("child:", child);