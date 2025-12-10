const acme = require('acme-client');
const fs = require('fs');
const path = require('path');
const http = require('http');
require('dotenv').config();

// Configuration from environment variables
const DOMAIN = process.env.DOMAIN || 'slackbot.kamayie.org';
const EMAIL = process.env.EMAIL || 'admin@example.com';
const STAGING = process.env.STAGING === 'true';
const NEW_CERT = process.env.NEW_CERT === 'true';
const CERTS_DIR = path.join(__dirname, 'certs');

// Challenge tokens storage for HTTP-01 validation
const challengeTokens = {};

// HTTP server for ACME HTTP-01 challenge
let challengeServer = null;

async function startChallengeServer() {
    return new Promise((resolve, reject) => {
        challengeServer = http.createServer((req, res) => {
            const prefix = '/.well-known/acme-challenge/';
            if (req.url.startsWith(prefix)) {
                const token = req.url.slice(prefix.length);
                const keyAuthorization = challengeTokens[token];

                if (keyAuthorization) {
                    console.log(`Serving challenge for token: ${token}`);
                    res.writeHead(200, { 'Content-Type': 'text/plain' });
                    res.end(keyAuthorization);
                } else {
                    console.log(`Challenge token not found: ${token}`);
                    res.writeHead(404);
                    res.end('Not found');
                }
            } else {
                res.writeHead(404);
                res.end('Not found');
            }
        });

        challengeServer.listen(80, () => {
            console.log('Challenge server listening on port 80');
            resolve();
        });

        challengeServer.on('error', (err) => {
            if (err.code === 'EACCES') {
                console.error('Error: Port 80 requires root privileges. Run with sudo.');
            }
            reject(err);
        });
    });
}

function stopChallengeServer() {
    return new Promise((resolve) => {
        if (challengeServer) {
            challengeServer.close(() => {
                console.log('Challenge server stopped');
                resolve();
            });
        } else {
            resolve();
        }
    });
}

async function challengeCreateFn(authz, challenge, keyAuthorization) {
    console.log(`Creating challenge for ${authz.identifier.value}`);

    if (challenge.type === 'http-01') {
        challengeTokens[challenge.token] = keyAuthorization;
        console.log(`Challenge token stored: ${challenge.token}`);
    }
}

async function challengeRemoveFn(authz, challenge) {
    console.log(`Removing challenge for ${authz.identifier.value}`);

    if (challenge.type === 'http-01') {
        delete challengeTokens[challenge.token];
    }
}

async function renewCertificate() {
    console.log('========================================');
    console.log('Let\'s Encrypt Certificate Renewal Tool');
    console.log('========================================');
    console.log(`Domain: ${DOMAIN}`);
    console.log(`Email: ${EMAIL}`);
    console.log(`Mode: ${STAGING ? 'STAGING (testing)' : 'PRODUCTION'}`);
    console.log(`Action: ${NEW_CERT ? 'Request NEW certificate' : 'Renew existing certificate'}`);
    console.log(`Certs directory: ${CERTS_DIR}`);
    console.log('========================================\n');

    // Ensure certs directory exists
    if (!fs.existsSync(CERTS_DIR)) {
        fs.mkdirSync(CERTS_DIR, { recursive: true });
        console.log('Created certs directory');
    }

    // If NEW_CERT is set, skip expiration check and request a fresh certificate
    if (NEW_CERT) {
        console.log('NEW_CERT=true: Requesting a fresh certificate (ignoring any existing certs)...');
    } else {
        // Check existing certificate expiration
        const certPath = path.join(CERTS_DIR, 'cert.pem');
        if (fs.existsSync(certPath)) {
            try {
                const certPem = fs.readFileSync(certPath, 'utf8');
                const certInfo = await acme.forge.readCertificateInfo(certPem);
                const daysUntilExpiry = Math.floor((certInfo.notAfter - new Date()) / (1000 * 60 * 60 * 24));

                console.log(`Existing certificate expires: ${certInfo.notAfter.toISOString()}`);
                console.log(`Days until expiry: ${daysUntilExpiry}`);

                if (daysUntilExpiry > 30) {
                    console.log('\nCertificate is still valid for more than 30 days.');
                    console.log('Set FORCE_RENEW=true to force renewal anyway.');
                    console.log('Set NEW_CERT=true to request a completely new certificate.');

                    if (process.env.FORCE_RENEW !== 'true') {
                        console.log('Skipping renewal.');
                        return;
                    }
                    console.log('FORCE_RENEW is set, proceeding with renewal...');
                }
            } catch (err) {
                console.log('Could not read existing certificate info, proceeding with renewal');
            }
        }
    }

    try {
        // Start HTTP challenge server
        await startChallengeServer();

        // Create ACME client
        const directoryUrl = STAGING
            ? acme.directory.letsencrypt.staging
            : acme.directory.letsencrypt.production;

        console.log(`\nUsing ACME directory: ${directoryUrl}`);

        const client = new acme.Client({
            directoryUrl,
            accountKey: await acme.forge.createPrivateKey()
        });

        // Register account
        console.log('\nRegistering ACME account...');
        await client.createAccount({
            termsOfServiceAgreed: true,
            contact: [`mailto:${EMAIL}`]
        });
        console.log('Account registered successfully');

        // Create CSR
        console.log('\nGenerating certificate signing request...');
        const [key, csr] = await acme.forge.createCsr({
            commonName: DOMAIN
        });

        // Order certificate
        console.log('\nOrdering certificate...');
        const cert = await client.auto({
            csr,
            email: EMAIL,
            termsOfServiceAgreed: true,
            challengeCreateFn,
            challengeRemoveFn
        });

        // Save certificates
        console.log('\nSaving certificates...');

        // Private key
        fs.writeFileSync(path.join(CERTS_DIR, 'privkey.pem'), key);
        console.log('  - privkey.pem (private key)');

        // Full certificate chain
        fs.writeFileSync(path.join(CERTS_DIR, 'fullchain.pem'), cert);
        console.log('  - fullchain.pem (full certificate chain)');

        // Parse the certificate to separate cert and chain
        const certs = cert.split(/(?=-----BEGIN CERTIFICATE-----)/);

        if (certs.length >= 1) {
            // The first certificate is the domain certificate
            fs.writeFileSync(path.join(CERTS_DIR, 'cert.pem'), certs[0]);
            console.log('  - cert.pem (domain certificate)');
        }

        if (certs.length >= 2) {
            // The rest is the certificate chain
            const chain = certs.slice(1).join('');
            fs.writeFileSync(path.join(CERTS_DIR, 'chain.pem'), chain);
            console.log('  - chain.pem (intermediate certificates)');
        }

        // Create bundle (fullchain + privkey for some applications)
        const bundle = cert + key;
        fs.writeFileSync(path.join(CERTS_DIR, 'bundle.pem'), bundle);
        console.log('  - bundle.pem (fullchain + private key)');

        console.log('\n========================================');
        console.log('Certificate renewal completed successfully!');
        console.log('========================================');

    } catch (err) {
        console.error('\nError during certificate renewal:');
        console.error(err.message);

        if (err.message.includes('rateLimited')) {
            console.error('\nRate limited by Let\'s Encrypt. Please wait before trying again.');
            console.error('For testing, set STAGING=true in your .env file.');
        }

        process.exit(1);
    } finally {
        await stopChallengeServer();
    }
}

// Run the renewal
renewCertificate().catch(console.error);
