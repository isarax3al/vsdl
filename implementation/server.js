/**
 * VSDL Server - Verifiable Smart Delegation Links
 * 
 * This server implements the VSDL protocol as described in the paper:
 * "Verifiable Smart Delegation Links: A Theoretical Framework 
 *  for Privacy-Preserving E-Government Delegation"
 * 
 * Endpoints:
 * - GET  /                     - Web interface
 * - GET  /api/generators       - Get cryptographic generators info
 * - POST /api/token/create     - Owner creates delegation token
 * - GET  /api/delegate/:token  - Delegate accesses filtered data
 * - POST /api/verify           - Verify server response
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pedersen = require('./pedersen');

const app = express();
app.use(express.json());
app.use(require('cors')());

// Server secret for JWT signing
const SERVER_SECRET = crypto.randomBytes(32).toString('hex');

// In-memory storage (production would use database)
const tokenStore = new Map();

// Sample citizen records (simulating government database)
const citizenDB = {
  'citizen-001': {
    name: 'Ahmed Ali Mohammed',
    nationalId: '1087654321',
    dateOfBirth: '1965-03-15',
    address: 'King Fahd Road, Riyadh 12345',
    phone: '+966501234567',
    email: 'ahmed@email.com',
    taxRecords: 'Annual Income: 180,000 SAR | Tax Paid: 4,500 SAR',
    bankAccount: 'SA4420000001234567891234',
    medicalHistory: 'Blood Type: O+ | Allergies: None | Conditions: Hypertension',
    propertyRecords: 'Villa in Riyadh (2.1M SAR) | Land in Jeddah (800K SAR)'
  }
};

// Predefined delegation policies
const POLICIES = {
  'id-renewal': {
    name: 'National ID Renewal',
    description: 'Access to basic identity information for ID renewal',
    visibleFields: ['name', 'nationalId', 'dateOfBirth', 'address'],
    hiddenFields: ['phone', 'email', 'taxRecords', 'bankAccount', 'medicalHistory', 'propertyRecords'],
    allowedActions: ['view_id_info', 'submit_renewal_application', 'upload_photo']
  },
  'tax-filing': {
    name: 'Tax Filing Assistance',
    description: 'Access to financial information for tax preparation',
    visibleFields: ['name', 'nationalId', 'taxRecords', 'bankAccount'],
    hiddenFields: ['dateOfBirth', 'address', 'phone', 'email', 'medicalHistory', 'propertyRecords'],
    allowedActions: ['view_tax_info', 'submit_tax_return', 'download_tax_certificate']
  },
  'medical-proxy': {
    name: 'Medical Appointment',
    description: 'Access to medical information for healthcare proxy',
    visibleFields: ['name', 'nationalId', 'dateOfBirth', 'medicalHistory'],
    hiddenFields: ['address', 'phone', 'email', 'taxRecords', 'bankAccount', 'propertyRecords'],
    allowedActions: ['view_medical_info', 'book_appointment', 'view_prescriptions']
  }
};

/**
 * Serve the web interface
 */
app.get('/', (req, res) => {
  res.send(getHTML());
});

/**
 * Get cryptographic generators information
 */
app.get('/api/generators', (req, res) => {
  const info = pedersen.getGeneratorInfo();
  res.json({
    success: true,
    data: info,
    explanation: {
      G: 'Standard generator of secp256k1 curve',
      H: 'Derived generator with unknown discrete log relation to G',
      importance: 'Unknown DL relationship ensures commitment binding property'
    }
  });
});

/**
 * Get available policies
 */
app.get('/api/policies', (req, res) => {
  res.json({
    success: true,
    policies: POLICIES
  });
});

/**
 * Create delegation token
 * 
 * This is called by the OWNER to create a delegation link
 */
app.post('/api/token/create', (req, res) => {
  try {
    const { citizenId, policyId, expiresIn = 3600 } = req.body;
    
    // Get citizen record
    const record = citizenDB[citizenId];
    if (!record) {
      return res.status(404).json({ success: false, error: 'Citizen not found' });
    }
    
    // Get policy
    const policy = POLICIES[policyId];
    if (!policy) {
      return res.status(400).json({ success: false, error: 'Invalid policy' });
    }
    
    // Generate unique token ID
    const tokenId = crypto.randomBytes(16).toString('hex');
    
    // Create Pedersen commitment to entire record
    const commitmentResult = pedersen.commitRecord(record);
    
    // Store token data server-side
    tokenStore.set(tokenId, {
      citizenId,
      policyId,
      record,
      policy,
      fieldCommitments: commitmentResult.fieldCommitments,
      recordCommitment: commitmentResult.recordCommitment,
      createdAt: Date.now()
    });
    
    // Compute policy hash
    const policyHash = crypto.createHash('sha256')
      .update(JSON.stringify({
        visible: policy.visibleFields.sort(),
        hidden: policy.hiddenFields.sort()
      }))
      .digest('hex');
    
    // Create JWT
    const jwtPayload = {
      jti: tokenId,
      sub: crypto.createHash('sha256').update(citizenId).digest('hex').slice(0, 16),
      policy: policyId,
      policyHash: policyHash.slice(0, 32),
      commitment: pedersen.serializePoint(commitmentResult.recordCommitment).compressed,
      actions: policy.allowedActions
    };
    
    const token = jwt.sign(jwtPayload, SERVER_SECRET, {
      expiresIn,
      issuer: 'vsdl-gov-portal'
    });
    
    // Generate delegation URL
    const delegationUrl = `http://localhost:3000/api/delegate/${encodeURIComponent(token)}`;
    
    res.json({
      success: true,
      data: {
        tokenId,
        token: token,
        delegationUrl,
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
        
        // Cryptographic details for display
        cryptography: {
          recordCommitment: pedersen.serializePoint(commitmentResult.recordCommitment),
          policyHash,
          math: commitmentResult.math,
          fieldCommitments: Object.fromEntries(
            Object.entries(commitmentResult.fieldCommitments).map(([k, v]) => [
              k,
              {
                commitment: pedersen.serializePoint(v.commitment),
                math: v.math
              }
            ])
          )
        },
        
        policy: {
          name: policy.name,
          visibleFields: policy.visibleFields,
          hiddenFields: policy.hiddenFields,
          allowedActions: policy.allowedActions
        }
      }
    });
    
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Delegate accesses data using token
 * 
 * This is called by the DELEGATE with the delegation link
 */
app.get('/api/delegate/:token', (req, res) => {
  try {
    const { token } = req.params;
    
    // Verify JWT
    let payload;
    try {
      payload = jwt.verify(token, SERVER_SECRET);
    } catch (err) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid or expired token',
        details: err.message 
      });
    }
    
    // Get stored data
    const stored = tokenStore.get(payload.jti);
    if (!stored) {
      return res.status(404).json({ success: false, error: 'Token data not found' });
    }
    
    const { record, policy, fieldCommitments, recordCommitment } = stored;
    
    // Filter data according to policy
    const filteredData = {};
    const visibleFieldsProof = [];
    
    for (const field of policy.visibleFields) {
      if (record[field] !== undefined) {
        filteredData[field] = record[field];
        visibleFieldsProof.push({
          fieldName: field,
          value: record[field],
          randomness: pedersen.serializeBN(fieldCommitments[field].randomness)
        });
      }
    }
    
    // Compute hidden commitment
    const hiddenFieldNames = policy.hiddenFields.filter(f => record[f] !== undefined);
    const { commitment: hiddenCommitment } = pedersen.computeSubsetCommitment(
      fieldCommitments, 
      hiddenFieldNames
    );
    
    // Compute visible commitment for verification display
    const { commitment: visibleCommitment } = pedersen.computeSubsetCommitment(
      fieldCommitments,
      policy.visibleFields.filter(f => record[f] !== undefined)
    );
    
    // Verify partition (for display)
    const verification = pedersen.verifyPartition(
      recordCommitment,
      hiddenCommitment,
      visibleCommitment
    );
    
    res.json({
      success: true,
      data: {
        // Filtered data the delegate can see
        filteredRecord: filteredData,
        allowedActions: policy.allowedActions,
        
        // Proof for verification
        proof: {
          recordCommitment: pedersen.serializePoint(recordCommitment),
          hiddenCommitment: pedersen.serializePoint(hiddenCommitment),
          visibleCommitment: pedersen.serializePoint(visibleCommitment),
          visibleFields: visibleFieldsProof,
          hiddenFieldCount: hiddenFieldNames.length,
          
          // The verification equation
          verification: verification.math
        },
        
        // Policy info
        policy: {
          name: policy.name,
          policyHash: payload.policyHash
        }
      }
    });
    
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Client-side verification endpoint
 * 
 * Delegate can independently verify the server's response
 */
app.post('/api/verify', (req, res) => {
  try {
    const { visibleFields, recordCommitment, hiddenCommitment } = req.body;
    
    // Recompute visible commitment from data + randomness
    const recomputed = pedersen.recomputeCommitment(visibleFields);
    
    // Deserialize commitments
    const C_D = pedersen.deserializePoint(recordCommitment);
    const C_H = pedersen.deserializePoint(hiddenCommitment);
    const C_F = recomputed.commitment;
    
    // Verify partition
    const verification = pedersen.verifyPartition(C_D, C_H, C_F);
    
    res.json({
      success: true,
      data: {
        valid: verification.valid,
        recomputedVisible: pedersen.serializePoint(C_F),
        recomputationDetails: recomputed.details,
        verification: verification.math,
        explanation: verification.valid 
          ? 'Server correctly filtered the data. C_D = C_H · C_F holds.'
          : 'WARNING: Verification failed! Server may have tampered with data.'
      }
    });
    
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * HTML Interface
 */
function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VSDL - Verifiable Smart Delegation Links</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Courier New', monospace;
      background: #fff;
      color: #000;
      line-height: 1.6;
      padding: 20px;
      max-width: 1400px;
      margin: 0 auto;
    }
    
    h1, h2, h3 {
      border-bottom: 2px solid #000;
      padding-bottom: 10px;
      margin-bottom: 20px;
    }
    
    h1 {
      font-size: 24px;
      text-transform: uppercase;
      letter-spacing: 2px;
    }
    
    h2 {
      font-size: 18px;
      margin-top: 30px;
    }
    
    h3 {
      font-size: 14px;
      border-bottom: 1px solid #000;
    }
    
    .section {
      border: 1px solid #000;
      padding: 20px;
      margin-bottom: 20px;
    }
    
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    
    @media (max-width: 900px) {
      .grid {
        grid-template-columns: 1fr;
      }
    }
    
    label {
      display: block;
      font-weight: bold;
      margin-bottom: 5px;
      text-transform: uppercase;
      font-size: 12px;
    }
    
    select, button {
      width: 100%;
      padding: 10px;
      border: 1px solid #000;
      background: #fff;
      font-family: inherit;
      font-size: 14px;
      margin-bottom: 15px;
    }
    
    button {
      background: #000;
      color: #fff;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 1px;
      transition: all 0.2s;
    }
    
    button:hover {
      background: #333;
    }
    
    button:disabled {
      background: #ccc;
      cursor: not-allowed;
    }
    
    .output {
      background: #f5f5f5;
      border: 1px solid #000;
      padding: 15px;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 400px;
      overflow-y: auto;
    }
    
    .math-box {
      background: #fff;
      border: 2px solid #000;
      padding: 20px;
      margin: 15px 0;
      font-family: 'Times New Roman', serif;
    }
    
    .math-box .formula {
      font-size: 18px;
      text-align: center;
      margin: 10px 0;
      font-style: italic;
    }
    
    .math-box .values {
      font-family: 'Courier New', monospace;
      font-size: 11px;
      margin-top: 15px;
    }
    
    .commitment-display {
      display: grid;
      grid-template-columns: 80px 1fr;
      gap: 5px;
      font-size: 11px;
      margin: 10px 0;
    }
    
    .commitment-display dt {
      font-weight: bold;
    }
    
    .commitment-display dd {
      font-family: 'Courier New', monospace;
      word-break: break-all;
    }
    
    .status {
      padding: 10px;
      text-align: center;
      font-weight: bold;
      margin: 10px 0;
    }
    
    .status.valid {
      background: #fff;
      border: 2px solid #000;
    }
    
    .status.invalid {
      background: #000;
      color: #fff;
    }
    
    .hidden-indicator {
      color: #666;
      font-style: italic;
    }
    
    .data-table {
      width: 100%;
      border-collapse: collapse;
      margin: 15px 0;
      font-size: 12px;
    }
    
    .data-table th, .data-table td {
      border: 1px solid #000;
      padding: 8px;
      text-align: left;
    }
    
    .data-table th {
      background: #000;
      color: #fff;
      text-transform: uppercase;
    }
    
    .flow-diagram {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin: 20px 0;
      padding: 20px;
      border: 1px solid #000;
    }
    
    .flow-step {
      text-align: center;
      flex: 1;
    }
    
    .flow-step .icon {
      font-size: 24px;
      margin-bottom: 10px;
    }
    
    .flow-arrow {
      font-size: 24px;
      padding: 0 10px;
    }
    
    .url-display {
      background: #f5f5f5;
      border: 1px solid #000;
      padding: 10px;
      font-size: 11px;
      word-break: break-all;
      margin: 10px 0;
    }
    
    #log {
      height: 200px;
      overflow-y: auto;
    }
    
    .log-entry {
      padding: 5px 0;
      border-bottom: 1px dotted #ccc;
      font-size: 11px;
    }
    
    .log-entry.error {
      color: #000;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <h1>VSDL — Verifiable Smart Delegation Links</h1>
  <p style="margin-bottom: 20px; font-size: 14px;">
    Proof of Concept Implementation | Cryptographic Delegation for E-Government
  </p>
  
  <div class="flow-diagram">
    <div class="flow-step">
      <div class="icon">[OWNER]</div>
      <div>Creates Token</div>
    </div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">
      <div class="icon">[SERVER]</div>
      <div>Stores Commitment</div>
    </div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">
      <div class="icon">[DELEGATE]</div>
      <div>Verifies & Accesses</div>
    </div>
  </div>
  
  <div class="grid">
    <!-- LEFT COLUMN: Owner Actions -->
    <div>
      <div class="section">
        <h2>1. Owner: Create Delegation Token</h2>
        
        <label>Select Citizen Record</label>
        <select id="citizenSelect">
          <option value="citizen-001">Ahmed Ali Mohammed (ID: 1087654321)</option>
        </select>
        
        <label>Select Delegation Policy</label>
        <select id="policySelect">
          <option value="id-renewal">National ID Renewal</option>
          <option value="tax-filing">Tax Filing Assistance</option>
          <option value="medical-proxy">Medical Appointment</option>
        </select>
        
        <button onclick="createToken()">Generate Delegation Token</button>
        
        <div id="tokenResult"></div>
      </div>
      
      <div class="section">
        <h2>2. Mathematical Foundation</h2>
        
        <div class="math-box">
          <h3>Pedersen Commitment Scheme</h3>
          <div class="formula">C = g<sup>m</sup> · h<sup>r</sup></div>
          <p style="font-size: 12px; margin-top: 10px;">
            Where g, h are generators of group G with unknown discrete log relationship,
            m is the message hash, and r is random blinding factor.
          </p>
        </div>
        
        <div class="math-box">
          <h3>Record Commitment</h3>
          <div class="formula">C<sub>D</sub> = ∏ C<sub>f<sub>i</sub>,v<sub>i</sub></sub></div>
          <p style="font-size: 12px; margin-top: 10px;">
            Homomorphic property allows combining individual field commitments.
          </p>
        </div>
        
        <div class="math-box">
          <h3>Verification Equation</h3>
          <div class="formula">C<sub>D</sub> = C<sub>H</sub> · C<sub>F</sub></div>
          <p style="font-size: 12px; margin-top: 10px;">
            Record commitment equals product of hidden and filtered commitments.
            This proves correct filtering without revealing hidden data.
          </p>
        </div>
        
        <button onclick="loadGenerators()">Show Curve Generators</button>
        <div id="generatorsDisplay"></div>
      </div>
    </div>
    
    <!-- RIGHT COLUMN: Delegate Actions -->
    <div>
      <div class="section">
        <h2>3. Delegate: Access Data via Token</h2>
        
        <label>Delegation URL (from Owner)</label>
        <input type="text" id="delegationUrl" style="width: 100%; padding: 10px; border: 1px solid #000; font-family: monospace; font-size: 11px;" placeholder="Paste delegation URL here...">
        
        <button onclick="accessAsDelegate()" style="margin-top: 10px;">Access Delegated Data</button>
        
        <div id="delegateResult"></div>
      </div>
      
      <div class="section">
        <h2>4. Cryptographic Verification</h2>
        
        <button onclick="verifyProof()" id="verifyBtn" disabled>Verify Server Response</button>
        
        <div id="verificationResult"></div>
      </div>
      
      <div class="section">
        <h2>5. Activity Log</h2>
        <div id="log" class="output"></div>
      </div>
    </div>
  </div>
  
  <div class="section">
    <h2>Full Cryptographic Details</h2>
    <div id="fullDetails" class="output" style="max-height: 600px;">
      Cryptographic details will appear here after operations...
    </div>
  </div>

  <script>
    let currentProof = null;
    
    function log(message, isError = false) {
      const logDiv = document.getElementById('log');
      const entry = document.createElement('div');
      entry.className = 'log-entry' + (isError ? ' error' : '');
      entry.textContent = new Date().toLocaleTimeString() + ' - ' + message;
      logDiv.insertBefore(entry, logDiv.firstChild);
    }
    
    function formatHex(hex, maxLen = 32) {
      if (!hex) return 'null';
      if (hex.length <= maxLen) return hex;
      return hex.slice(0, maxLen/2) + '...' + hex.slice(-maxLen/2);
    }
    
    async function loadGenerators() {
      try {
        log('Loading curve generators...');
        const res = await fetch('/api/generators');
        const data = await res.json();
        
        if (data.success) {
          document.getElementById('generatorsDisplay').innerHTML = \`
            <div class="math-box">
              <h3>secp256k1 Curve Parameters</h3>
              <dl class="commitment-display">
                <dt>Curve:</dt><dd>\${data.data.curve.name}</dd>
                <dt>p:</dt><dd>\${formatHex(data.data.curve.p)}</dd>
                <dt>n:</dt><dd>\${formatHex(data.data.curve.n)}</dd>
              </dl>
              <h3>Generator G (Standard)</h3>
              <dl class="commitment-display">
                <dt>x:</dt><dd>\${formatHex(data.data.G.x)}</dd>
                <dt>y:</dt><dd>\${formatHex(data.data.G.y)}</dd>
              </dl>
              <h3>Generator H (Derived)</h3>
              <dl class="commitment-display">
                <dt>x:</dt><dd>\${formatHex(data.data.H.x)}</dd>
                <dt>y:</dt><dd>\${formatHex(data.data.H.y)}</dd>
              </dl>
              <p style="font-size: 11px; margin-top: 10px;">
                <strong>Note:</strong> \${data.explanation.importance}
              </p>
            </div>
          \`;
          log('Generators loaded successfully');
        }
      } catch (err) {
        log('Error: ' + err.message, true);
      }
    }
    
    async function createToken() {
      try {
        const citizenId = document.getElementById('citizenSelect').value;
        const policyId = document.getElementById('policySelect').value;
        
        log('Creating delegation token...');
        log('Policy: ' + policyId);
        
        const res = await fetch('/api/token/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ citizenId, policyId, expiresIn: 3600 })
        });
        
        const data = await res.json();
        
        if (data.success) {
          // Display token result
          document.getElementById('tokenResult').innerHTML = \`
            <div class="status valid">TOKEN CREATED SUCCESSFULLY</div>
            
            <h3>Delegation URL (Share with Delegate)</h3>
            <div class="url-display">\${data.data.delegationUrl}</div>
            <button onclick="navigator.clipboard.writeText('\${data.data.delegationUrl}'); log('URL copied!');">
              Copy URL
            </button>
            
            <h3>Policy Applied</h3>
            <table class="data-table">
              <tr><th>Visible Fields</th><td>\${data.data.policy.visibleFields.join(', ')}</td></tr>
              <tr><th>Hidden Fields</th><td>\${data.data.policy.hiddenFields.join(', ')}</td></tr>
              <tr><th>Allowed Actions</th><td>\${data.data.policy.allowedActions.join(', ')}</td></tr>
            </table>
            
            <h3>Record Commitment C<sub>D</sub></h3>
            <dl class="commitment-display">
              <dt>x:</dt><dd>\${data.data.cryptography.recordCommitment.x}</dd>
              <dt>y:</dt><dd>\${data.data.cryptography.recordCommitment.y}</dd>
            </dl>
          \`;
          
          // Auto-fill delegation URL
          document.getElementById('delegationUrl').value = data.data.delegationUrl;
          
          // Show full details
          document.getElementById('fullDetails').textContent = JSON.stringify(data.data.cryptography, null, 2);
          
          log('Token created: ' + data.data.tokenId);
          log('Expires: ' + data.data.expiresAt);
        } else {
          log('Error: ' + data.error, true);
        }
      } catch (err) {
        log('Error: ' + err.message, true);
      }
    }
    
    async function accessAsDelegate() {
      try {
        const url = document.getElementById('delegationUrl').value;
        if (!url) {
          log('Error: No delegation URL provided', true);
          return;
        }
        
        log('Accessing delegated data...');
        
        const res = await fetch(url);
        const data = await res.json();
        
        if (data.success) {
          currentProof = data.data.proof;
          document.getElementById('verifyBtn').disabled = false;
          
          // Display filtered data
          let tableRows = '';
          for (const [field, value] of Object.entries(data.data.filteredRecord)) {
            tableRows += \`<tr><td>\${field}</td><td>\${value}</td></tr>\`;
          }
          
          document.getElementById('delegateResult').innerHTML = \`
            <div class="status valid">DATA RECEIVED</div>
            
            <h3>Filtered Record (What Delegate Sees)</h3>
            <table class="data-table">
              <tr><th>Field</th><th>Value</th></tr>
              \${tableRows}
            </table>
            
            <p class="hidden-indicator">
              + \${data.data.proof.hiddenFieldCount} hidden fields (cryptographically protected)
            </p>
            
            <h3>Allowed Actions</h3>
            <p>\${data.data.allowedActions.join(', ')}</p>
            
            <h3>Proof Components</h3>
            <div class="math-box">
              <div class="formula">C<sub>D</sub> = C<sub>H</sub> · C<sub>F</sub></div>
              <dl class="commitment-display">
                <dt>C<sub>D</sub> (x):</dt><dd>\${formatHex(data.data.proof.recordCommitment.x)}</dd>
                <dt>C<sub>H</sub> (x):</dt><dd>\${formatHex(data.data.proof.hiddenCommitment.x)}</dd>
                <dt>C<sub>F</sub> (x):</dt><dd>\${formatHex(data.data.proof.visibleCommitment.x)}</dd>
              </dl>
            </div>
          \`;
          
          document.getElementById('fullDetails').textContent = JSON.stringify(data.data, null, 2);
          
          log('Data received: ' + Object.keys(data.data.filteredRecord).length + ' visible fields');
          log('Hidden fields: ' + data.data.proof.hiddenFieldCount);
        } else {
          log('Error: ' + data.error, true);
          document.getElementById('delegateResult').innerHTML = \`
            <div class="status invalid">ACCESS DENIED: \${data.error}</div>
          \`;
        }
      } catch (err) {
        log('Error: ' + err.message, true);
      }
    }
    
    async function verifyProof() {
      try {
        if (!currentProof) {
          log('Error: No proof to verify', true);
          return;
        }
        
        log('Verifying cryptographic proof...');
        
        const res = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            visibleFields: currentProof.visibleFields,
            recordCommitment: currentProof.recordCommitment.compressed,
            hiddenCommitment: currentProof.hiddenCommitment.compressed
          })
        });
        
        const data = await res.json();
        
        if (data.success) {
          const v = data.data.verification;
          
          document.getElementById('verificationResult').innerHTML = \`
            <div class="status \${data.data.valid ? 'valid' : 'invalid'}">
              VERIFICATION: \${data.data.valid ? 'PASSED ✓' : 'FAILED ✗'}
            </div>
            
            <div class="math-box">
              <h3>Verification Equation</h3>
              <div class="formula">\${v.equation}</div>
              
              <h3>Computed Values</h3>
              <dl class="commitment-display">
                <dt>C<sub>D</sub>:</dt><dd>\${formatHex(v.C_D.x)}</dd>
                <dt>C<sub>H</sub>:</dt><dd>\${formatHex(v.C_H.x)}</dd>
                <dt>C<sub>F</sub>:</dt><dd>\${formatHex(v.C_F.x)}</dd>
                <dt>C<sub>H</sub>·C<sub>F</sub>:</dt><dd>\${formatHex(v.sum.x)}</dd>
              </dl>
              
              <h3>Result</h3>
              <p style="text-align: center; font-size: 16px; font-weight: bold;">
                \${v.result}
              </p>
            </div>
            
            <p style="margin-top: 15px;">
              <strong>Explanation:</strong> \${data.data.explanation}
            </p>
          \`;
          
          log('Verification complete: ' + (data.data.valid ? 'VALID' : 'INVALID'));
        }
      } catch (err) {
        log('Error: ' + err.message, true);
      }
    }
    
    // Initial log
    log('VSDL Server ready');
    log('Click "Generate Delegation Token" to start');
  </script>
</body>
</html>`;
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('============================================================');
  console.log('VSDL Server Running');
  console.log('============================================================');
  console.log('Local:   http://localhost:' + PORT);
  console.log('');
  console.log('This server implements:');
  console.log('- Pedersen commitments for data fields');
  console.log('- JWT-based delegation tokens');
  console.log('- Verifiable data filtering');
  console.log('- Cryptographic proof verification');
  console.log('============================================================');
});
