/**
 * Test file with TypeScript crypto usage for CBOMScan fixture.
 * Tests TypeScript-specific patterns.
 */

import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import * as crypto from 'crypto';
import { subtle } from 'crypto/webcrypto';

// ===== jsonwebtoken with RS256 (TypeScript) =====
function createJWTWithRS256TS(): string {
    const payload = { userId: 123, role: 'admin' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`;

    // This should be detected as RSA (RS256 = RSA signature)
    const token: string = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
    return token;
}

function verifyJWTWithRS256TS(token: string): object {
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

    // This should also be detected
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    return decoded;
}

// ===== jose library with ECDSA =====
async function generateECDSAWithJose(): Promise<CryptoKeyPair> {
    // jose uses Web Crypto API under the hood
    const keyPair = await jose.generateKeyPair('ES256', {
        extractable: true,
    });
    return keyPair;
}

async function signWithJose(keyPair: CryptoKeyPair, payload: object): Promise<string> {
    // This should be detected as ECDSA
    const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);
    return token;
}

async function verifyWithJose(token: string, publicKey: CryptoKey): Promise<jose.JWTPayload> {
    // This should be detected as ECDSA verification
    const { payload } = await jose.jwtVerify(token, publicKey, {
        algorithms: ['ES256'],
    });
    return payload;
}

// ===== jose with RSA =====
async function generateRSAWithJose(): Promise<CryptoKeyPair> {
    // This should be detected as RSA
    const keyPair = await jose.generateKeyPair('RS256', {
        extractable: true,
    });
    return keyPair;
}

async function signRSAWithJose(keyPair: CryptoKeyPair, payload: object): Promise<string> {
    const token = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(keyPair.privateKey);
    return token;
}

// ===== Web Crypto API with ECDSA (TypeScript) =====
async function generateECDSAKeyPairTS(): Promise<CryptoKeyPair> {
    // This should be detected as ECDSA
    const keyPair = await subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true,
        ['sign', 'verify']
    );
    return keyPair;
}

async function signWithECDSATS(keyPair: CryptoKeyPair, data: string): Promise<ArrayBuffer> {
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

// ===== Node.js crypto module (TypeScript) =====
function generateRSAKeyPairNodeTS(): crypto.KeyPairKeyObjectResult {
    // This should be detected as RSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function generateECKeyPairNodeTS(): crypto.KeyPairKeyObjectResult {
    // This should be detected as ECDSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}

function createSignNodeTS(): crypto.Sign {
    // This should be detected as RSA signature
    const sign = crypto.createSign('RSA-SHA256');
    sign.update('test data');
    return sign;
}

function createECDHNodeTS(): crypto.ECDH {
    // This should be detected as ECDH
    const ecdh = crypto.createECDH('secp256r1');
    ecdh.generateKeys();
    return ecdh;
}

// ===== JWT algorithm strings (TypeScript) =====
function jwtWithES256TS(): string {
    const payload = { data: 'test' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----`;

    // This should be detected as ECDSA (ES256 = ECDSA with P-256)
    const token: string = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
    return token;
}

function jwtWithHS256TS(): string {
    const payload = { data: 'test' };
    const secret = 'my-secret-key';

    // This should be detected as HMAC
    const token: string = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return token;
}

function jwtWithPS256TS(): string {
    const payload = { data: 'test' };
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`;

    // This should be detected as RSA (PS256 = RSA-PSS)
    const token: string = jwt.sign(payload, privateKey, { algorithm: 'PS256' });
    return token;
}

// Run examples
if (require.main === module) {
    console.log('TypeScript crypto examples...');

    console.log('\nCreating JWT with RS256...');
    const token = createJWTWithRS256TS();
    console.log('Token:', token.substring(0, 50) + '...');

    console.log('\nGenerating ECDSA key pair with jose...');
    generateECDSAWithJose().then(keyPair => {
        console.log('ECDSA key pair generated');
        return signWithJose(keyPair, { data: 'test' });
    }).then(token => {
        console.log('JWT token:', token.substring(0, 50) + '...');
    });

    console.log('\nGenerating RSA key pair with Node crypto...');
    const rsaKeys = generateRSAKeyPairNodeTS();
    console.log('RSA keys generated');

    console.log('\nCreating JWT with ES256...');
    const es256Token = jwtWithES256TS();
    console.log('ES256 token:', es256Token.substring(0, 50) + '...');

    console.log('\nDone!');
}

export {
    createJWTWithRS256TS,
    verifyJWTWithRS256TS,
    generateECDSAWithJose,
    signWithJose,
    verifyWithJose,
    generateRSAWithJose,
    signRSAWithJose,
    generateECDSAKeyPairTS,
    signWithECDSATS,
    generateRSAKeyPairNodeTS,
    generateECKeyPairNodeTS,
    createSignNodeTS,
    createECDHNodeTS,
    jwtWithES256TS,
    jwtWithHS256TS,
    jwtWithPS256TS,
};