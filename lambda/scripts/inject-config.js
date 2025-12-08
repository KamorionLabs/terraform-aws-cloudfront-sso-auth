/**
 * Inject SAML configuration into the built Lambda code
 * Lambda@Edge cannot access environment variables or Secrets Manager at runtime,
 * so we bake the configuration directly into the code at build time.
 */

const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, '../dist/shared/config.js');

// Read configuration from environment variables (set by Terraform)
const config = {
  audience: process.env.SAML_AUDIENCE || 'PLACEHOLDER_AUDIENCE',
  initVector: process.env.SAML_INIT_VECTOR || 'PLACEHOLDER_IV__', // 16 chars
  privateKey: process.env.SAML_PRIVATE_KEY || 'PLACEHOLDER_PRIVATE_KEY_32CHARS_', // 32 chars
  idpMetadata: process.env.SAML_IDP_METADATA || 'PLACEHOLDER_IDP_METADATA',
};

// Read the compiled config file
let content = fs.readFileSync(CONFIG_FILE, 'utf8');

// Replace placeholders with actual values
content = content.replace(/'PLACEHOLDER_AUDIENCE'/g, JSON.stringify(config.audience));
content = content.replace(/'PLACEHOLDER_IV__'/g, JSON.stringify(config.initVector));
content = content.replace(/'PLACEHOLDER_PRIVATE_KEY_32CHARS_'/g, JSON.stringify(config.privateKey));
content = content.replace(/'PLACEHOLDER_IDP_METADATA'/g, JSON.stringify(config.idpMetadata));

// Write back
fs.writeFileSync(CONFIG_FILE, content);

console.log('Configuration injected successfully');
