"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(aesKey,macKey) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */

    };
    this.secrets = {
      "aeskey" : aesKey,
      "mackey" : macKey,
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };

  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new Error("Password too long");
    }

    const salt =  getRandomBytes(128); 
    let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2",false,["deriveKey"])
    const masterkey = await subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      rawKey,
      { name: 'HMAC', hash : 'SHA-256' },
      false,
      ["sign","verify"]
  
    );
    
    const domain_identifier = await subtle.sign("HMAC", masterkey, stringToBuffer("domain-key"));
    const password_identifier = await subtle.sign("HMAC", masterkey, stringToBuffer("password-key"));
  

    let aesKey = await subtle.importKey("raw", password_identifier, "AES-GCM",true,["encrypt","decrypt"])
    let macKey = await subtle.importKey("raw", domain_identifier,{name : "HMAC", hash : "SHA-256"},true,["sign","verify"])
    const Key_chain = new Keychain(aesKey, macKey);
    return Key_chain;


  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
   
  static async load(password, repr, trustedDataCheck) {
    throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (!name) {
      throw new Error("Domain name cannot be empty");
    }
    
    const domainHmac = await subtle.sign("HMAC", this.secrets.mackey, stringToBuffer(name));
    const domainKey = bufferToString(domainHmac);

    // Check if an entry exists for the HMAC
    if (!(domainKey in this.data)) {
        return null; // No entry found
    }

    const encryptedData = this.data[domainKey];

    // Explicit null check before decryption
    if (!encryptedData) {
        return null; // Handle missing data for non-existent domains
    }

    const iv = encryptedData.iv;
    const decryptedData = await subtle.decrypt({ name: 'AES-GCM', iv }, this.secrets.aeskey, encryptedData.ciphertext);

    return bufferToString(decryptedData);
}

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (!name || !value) {
      throw new Error("Domain name and value must not be empty");
    }
    const iv = getRandomBytes(12);
    const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv }, this.secrets.aeskey, stringToBuffer(value));
    const domainHmac = await subtle.sign("HMAC", this.secrets.mackey, stringToBuffer(name));
    
    // Ensure consistent data format
    this.data[bufferToString(domainHmac)] = {
      iv,
      ciphertext: encryptedData,
    };
}

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }
