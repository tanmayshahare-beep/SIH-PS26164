/**
 * Test file with JavaScript crypto usage for CBOMScan fixture.
 * Tests:
 * - jsonwebtoken with RS256 (RSA)
 * - Web Crypto API with ECDSA
 * - Node.js crypto module with generateKeyPair
 */

const jwt = require('jsonwebtoken');
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

// ===== jsonwebtoken with RS256 =====
function createJWTWithRS256() {
    const payload = { userId: 123, role: 'admin' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`;

    // This should be detected as RSA (RS256 = RSA signature)
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
    return token;
}

function verifyJWTWithRS256(token) {
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

    // This should also be detected
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    return decoded;
}

// ===== Web Crypto API with ECDSA =====
async function generateECDSAKeyPair() {
    // This should be detected as ECDSA
    const keyPair = await subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true, // extractable
        ['sign', 'verify']
    );
    return keyPair;
}

async function signWithECDSA(keyPair, data) {
    const encodedData = new TextEncoder().encode(data);
    // This should be detected as ECDSA signature
    const signature = await subtle.sign(
        {
            name: 'ECDSA',
            hash: 'SHA-256',
        },
        keyPair.privateKey,
        encodedData
    );
    return signature;
}

async function verifyWithECDSA(keyPair, data, signature) {
    const encodedData = new TextEncoder().encode(data);
    // This should be detected as ECDSA verification
    const result = await subtle.verify(
        {
            name: 'ECDSA',
            hash: 'SHA-256',
        },
        keyPair.publicKey,
        signature,
        encodedData
    );
    return result;
}

async function generateRSAKeyPairWebCrypto() {
    // This should be detected as RSA
    const keyPair = await subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
    );
    return keyPair;
}

async function generateRSASSAKeyPair() {
    // This should be detected as RSA signature
    const keyPair = await subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
    );
    return keyPair;
}

async function generateRSA_PSS_KeyPair() {
    // This should be detected as RSA signature (RSA-PSS)
    const keyPair = await subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
    );
    return keyPair;
}

async function generateECDHKeyPair() {
    // This should be detected as ECDH
    const keyPair = await subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
    );
    return keyPair;
}

// ===== Node.js crypto module =====
function generateRSAKeyPairNode() {
    // This should be detected as RSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function generateECKeyPairNode() {
    // This should be detected as ECDSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function generateEd25519KeyPairNode() {
    // This should be detected as Ed25519
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function generateDHKeyPairNode() {
    // This should be detected as DH
    const { publicKey, privateKey } = crypto.generateKeyPairSync('dh', {
        primeLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function createSignNode() {
    // This should be detected as RSA signature
    const sign = crypto.createSign('RSA-SHA256');
    sign.update('test data');
    return sign;
}

function createECDHNode() {
    // This should be detected as ECDH
    const ecdh = crypto.createECDH('secp256r1');
    ecdh.generateKeys();
    return ecdh;
}

// ===== JWT algorithm strings in options =====
function jwtWithES256() {
    const payload = { data: 'test' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----`;

    // This should be detected as ECDSA (ES256 = ECDSA with P-256)
    const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
    return token;
}

function jwtWithHS256() {
    const payload = { data: 'test' };
    const secret = 'my-secret-key';

    // This should be detected as HMAC
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return token;
}

function jwtWithPS256() {
    const payload = { data: 'test' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`;

    // This should be detected as RSA (PS256 = RSA-PSS)
    const token = jwt.sign(payload, privateKey, { algorithm: 'PS256' });
    return token;
}

// Run examples
if (require.main === module) {
    console.log('Creating JWT with RS256...');
    const token = createJWTWithRS256();
    console.log('Token:', token.substring(0, 50) + '...');

    console.log('\nGenerating ECDSA key pair with Web Crypto...');
    generateECDSAKeyPair().then(keyPair => {
        console.log('ECDSA key pair generated');
        return signWithECDSA(keyPair, 'test message');
    }).then(signature => {
        console.log('Signature length:', signature.byteLength);
    });

    console.log('\nGenerating RSA key pair with Node crypto...');
    const rsaKeys = generateRSAKeyPairNode();
    console.log('RSA keys generated');

    console.log('\nGenerating EC key pair with Node crypto...');
    const ecKeys = generateECKeyPairNode();
    console.log('EC keys generated');

    console.log('\nCreating JWT with ES256...');
    const es256Token = jwtWithES256();
    console.log('ES256 token:', es256Token.substring(0, 50) + '...');

    console.log('\nCreating JWT with HS256...');
    const hs256Token = jwtWithHS256();
    console.log('HS256 token:', hs256Token.substring(0, 50) + '...');

    console.log('\nDone!');
}

module.exports = {
    createJWTWithRS256,
    verifyJWTWithRS256,
    generateECDSAKeyPair,
    signWithECDSA,
    verifyWithECDSA,
    generateRSAKeyPairWebCrypto,
    generateRSASSAKeyPair,
    generateRSA_PSS_KeyPair,
    generateECDHKeyPair,
    generateRSAKeyPairNode,
    generateECKeyPairNode,
    generateEd25519KeyPairNode,
    generateDHKeyPairNode,
    createSignNode,
    createECDHNode,
    jwtWithES256,
    jwtWithHS256,
    jwtWithPS256,
};