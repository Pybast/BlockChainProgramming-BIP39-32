const prompt = require("prompt-sync")();
const crypto = require("crypto");
var fs = require('fs');

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

console.log("random int", num);
var bits_array = int_to_bits_array(num, 128);
console.log("conversion to bits array", bits_array);

var hash = crypto.createHash('sha256');

hash.update(buf);

const hash_last_4 = int_to_bits_array(hash.digest()[0], 4)

const entropy = bits_array.concat(hash_last_4);

console.log(entropy);
console.log(entropy.length);

// loads bip39 txt file

var bip39txt;

try {  
    var data = fs.readFileSync('bip39.txt', 'utf8');
    bip39txt = data.toString();
} catch(e) {
    console.log('Error:', e.stack);
}

const bip39arr = bip39txt.split("\n").slice(0, bip39txt.split("\n").length - 1); // split then eject the last element as it's jsut an empty string

console.log(bip39arr.length);

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
        console.log(bits.slice(i, i+4), sum);
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

console.log("Voici votre entropy mnemonic:", mnemonic_entropy.join(" "));

console.log("Voici votre entropy hex", bits_to_hex(entropy));

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
            console.log("valid");
            return true;
        }
    };
}

var imported_mnemonic = "night bag green explain keen cheese fancy shop maple apple bind arm";//prompt("Merci d'importer une mnemonic.");

// if entered mnemonic is valid
while (!valid_mnemonic(imported_mnemonic)){
    imported_mnemonic = prompt("Erreur, merci d'importer une autre mnemonic.");
}

var imported_mnemonic_bits = [];

imported_mnemonic.split(" ").forEach((word) => {
    imported_mnemonic_bits = imported_mnemonic_bits.concat(mnemonic_word_to_bits(word));
});

console.log(imported_mnemonic_bits);

console.log(bits_to_hex(imported_mnemonic_bits).length, " -> ", bits_to_hex(imported_mnemonic_bits));

// Derivation de la seed
function hmac_sha512(data){
    var signed = data;
    for (var i = 0; i < 129; i++){
        var hmac = crypto.createHmac("sha512", "");
        signed = hmac.update(Buffer.from(signed, "hex")).digest('hex');
        console.log(signed);
    }
    return signed;
}

console.log(hmac_sha512(bits_to_hex(imported_mnemonic_bits)));

