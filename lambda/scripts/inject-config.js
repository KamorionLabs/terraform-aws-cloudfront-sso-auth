/**
 * Inject SAML configuration into the built Lambda code
 * Lambda@Edge cannot access environment variables or Secrets Manager at runtime,
 * so we bake the configuration directly into the code at build time.
 *
 * Config is read from:
 * 1. .saml-config.json file (created by Terraform) - preferred
 * 2. Environment variables (legacy fallback)
 */

const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, '../dist/shared/config.js');
const SAML_CONFIG_FILE = path.join(__dirname, '../.saml-config.json');

// Try to read config from JSON file first (created by Terraform)
let config;
if (fs.existsSync(SAML_CONFIG_FILE)) {
  console.log('Reading config from .saml-config.json');
  const jsonConfig = JSON.parse(fs.readFileSync(SAML_CONFIG_FILE, 'utf8'));
  config = {
    audience: jsonConfig.audience,
    initVector: jsonConfig.initVector,
    privateKey: jsonConfig.privateKey,
    idpMetadata: jsonConfig.idpMetadata,
    signingCert: jsonConfig.signingCert,
    signingPrivateKey: jsonConfig.signingPrivateKey,
    signAuthnRequests: jsonConfig.signAuthnRequests,
  };
} else {
  // Fallback to environment variables (legacy)
  console.log('Reading config from environment variables');
  config = {
    audience: process.env.SAML_AUDIENCE || 'PLACEHOLDER_AUDIENCE',
    initVector: process.env.SAML_INIT_VECTOR || 'PLACEHOLDER_IV__',
    privateKey: process.env.SAML_PRIVATE_KEY || 'PLACEHOLDER_PRIVATE_KEY_32CHARS_',
    idpMetadata: process.env.SAML_IDP_METADATA || 'PLACEHOLDER_IDP_METADATA',
    signingCert: process.env.SAML_SIGNING_CERT || 'PLACEHOLDER_SIGNING_CERT',
    signingPrivateKey: process.env.SAML_SIGNING_PRIVATE_KEY || 'PLACEHOLDER_SIGNING_PRIVATE_KEY',
    signAuthnRequests: process.env.SAML_SIGN_AUTHN_REQUESTS || 'false',
  };
}

// Validate config - ensure no placeholders remain
const hasPlaceholders = Object.values(config).some(v =>
  typeof v === 'string' && v.includes('PLACEHOLDER')
);
if (hasPlaceholders) {
  console.error('ERROR: Config contains placeholders. Run terraform apply to generate .saml-config.json');
  process.exit(1);
}

// Read the compiled config file
let content = fs.readFileSync(CONFIG_FILE, 'utf8');

// Replace placeholders with actual values
content = content.replace(/'PLACEHOLDER_AUDIENCE'/g, JSON.stringify(config.audience));
content = content.replace(/'PLACEHOLDER_IV__'/g, JSON.stringify(config.initVector));
content = content.replace(/'PLACEHOLDER_PRIVATE_KEY_32CHARS_'/g, JSON.stringify(config.privateKey));
content = content.replace(/'PLACEHOLDER_IDP_METADATA'/g, JSON.stringify(config.idpMetadata));
content = content.replace(/'PLACEHOLDER_SIGNING_CERT'/g, JSON.stringify(config.signingCert));
content = content.replace(/'PLACEHOLDER_SIGNING_PRIVATE_KEY'/g, JSON.stringify(config.signingPrivateKey));
content = content.replace(/'PLACEHOLDER_SIGN_AUTHN_REQUESTS'/g, JSON.stringify(config.signAuthnRequests));

// Write back
fs.writeFileSync(CONFIG_FILE, content);

console.log('Configuration injected successfully');
