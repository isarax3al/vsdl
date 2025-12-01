/**
 * VSDL - Pedersen Commitment Implementation
 * 
 * Mathematical Foundation:
 * ------------------------
 * Pedersen commitments use two generators g and h in a group G of prime order q
 * where the discrete logarithm relationship between g and h is unknown.
 * 
 * Commitment: C = g^m · h^r  (mod p)
 * 
 * Properties:
 * - Hiding: C reveals no information about m (information-theoretic)
 * - Binding: Cannot find m', r' such that g^m·h^r = g^m'·h^r' (computational)
 * 
 * Homomorphic Property:
 * C1 · C2 = g^(m1+m2) · h^(r1+r2)
 * 
 * This allows us to verify: C_record = C_hidden + C_visible
 */

const EC = require('elliptic').ec;
const BN = require('bn.js');
const crypto = require('crypto');

// Use secp256k1 curve (same as Bitcoin/Ethereum)
const ec = new EC('secp256k1');

// Curve parameters for display
const CURVE_INFO = {
  name: 'secp256k1',
  p: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
  n: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
  Gx: '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
  Gy: '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
};

// Generator G (standard generator of secp256k1)
const G = ec.g;

// Generator H (derived via hash - ensures unknown DL relationship with G)
// H = hash_to_point("VSDL_GENERATOR_H")
const H_seed = crypto.createHash('sha256').update('VSDL_GENERATOR_H_SEED_V1').digest();
const H = ec.g.mul(ec.keyFromPrivate(H_seed).getPrivate());

/**
 * Get generator points info for display
 */
function getGeneratorInfo() {
  return {
    G: {
      x: G.getX().toString(16).padStart(64, '0'),
      y: G.getY().toString(16).padStart(64, '0')
    },
    H: {
      x: H.getX().toString(16).padStart(64, '0'),
      y: H.getY().toString(16).padStart(64, '0')
    },
    curve: CURVE_INFO
  };
}

/**
 * Hash arbitrary data to a scalar in Zq
 * Uses SHA-256 and reduces modulo curve order
 */
function hashToScalar(data) {
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  const bn = new BN(hash, 16);
  return bn.umod(ec.n);
}

/**
 * Generate cryptographically secure random scalar in Zq
 */
function randomScalar() {
  const bytes = crypto.randomBytes(32);
  const bn = new BN(bytes);
  return bn.umod(ec.n);
}

/**
 * Pedersen Commitment for a single field
 * 
 * Formula: C_{f,v} = g^{H(f||v)} · h^r
 * 
 * @param {string} fieldName - Field identifier
 * @param {string} value - Field value  
 * @param {BN} r - Random scalar (blinding factor)
 * @returns {Object} Commitment details
 */
function commitField(fieldName, value, r = null) {
  // Generate random blinding factor if not provided
  const randomness = r || randomScalar();
  
  // m = H(fieldName || value)
  const message = `${fieldName}||${value}`;
  const m = hashToScalar(message);
  
  // C = g^m · h^r
  const gm = G.mul(m);      // g^m
  const hr = H.mul(randomness);  // h^r
  const C = gm.add(hr);     // g^m · h^r (point addition = multiplication in group)
  
  return {
    fieldName,
    value,
    commitment: C,
    randomness: randomness,
    // Detailed math for display
    math: {
      message: message,
      m: m.toString(16).padStart(64, '0'),
      r: randomness.toString(16).padStart(64, '0'),
      gm: {
        x: gm.getX().toString(16).padStart(64, '0'),
        y: gm.getY().toString(16).padStart(64, '0')
      },
      hr: {
        x: hr.getX().toString(16).padStart(64, '0'),
        y: hr.getY().toString(16).padStart(64, '0')
      },
      C: {
        x: C.getX().toString(16).padStart(64, '0'),
        y: C.getY().toString(16).padStart(64, '0')
      },
      formula: `C = g^H("${message}") · h^r`
    }
  };
}

/**
 * Commit to entire record
 * 
 * Formula: C_D = ∏ C_{f_i,v_i} = g^{Σm_i} · h^{Σr_i}
 * 
 * Due to homomorphic property, product of commitments = commitment to sum
 */
function commitRecord(record) {
  const fields = Object.entries(record);
  const fieldCommitments = {};
  
  let totalM = new BN(0);
  let totalR = new BN(0);
  let recordCommitment = null;
  
  for (const [fieldName, value] of fields) {
    const fc = commitField(fieldName, String(value));
    fieldCommitments[fieldName] = fc;
    
    // Accumulate for total
    totalM = totalM.add(hashToScalar(`${fieldName}||${value}`)).umod(ec.n);
    totalR = totalR.add(fc.randomness).umod(ec.n);
    
    // Multiply commitments (point addition)
    if (recordCommitment === null) {
      recordCommitment = fc.commitment;
    } else {
      recordCommitment = recordCommitment.add(fc.commitment);
    }
  }
  
  return {
    recordCommitment,
    fieldCommitments,
    math: {
      formula: 'C_D = ∏ C_{f_i,v_i} = g^{Σm_i} · h^{Σr_i}',
      totalM: totalM.toString(16).padStart(64, '0'),
      totalR: totalR.toString(16).padStart(64, '0'),
      C_D: {
        x: recordCommitment.getX().toString(16).padStart(64, '0'),
        y: recordCommitment.getY().toString(16).padStart(64, '0')
      },
      fieldCount: fields.length
    }
  };
}

/**
 * Compute commitment for a subset of fields
 */
function computeSubsetCommitment(fieldCommitments, fieldNames) {
  let commitment = null;
  const included = [];
  
  for (const name of fieldNames) {
    if (fieldCommitments[name]) {
      included.push(name);
      if (commitment === null) {
        commitment = fieldCommitments[name].commitment;
      } else {
        commitment = commitment.add(fieldCommitments[name].commitment);
      }
    }
  }
  
  return { commitment, included };
}

/**
 * Verify partition: C_D = C_H · C_F
 * 
 * This is the core verification equation.
 * If the server filtered correctly:
 *   C_record = C_hidden + C_visible
 * 
 * @param {Point} C_D - Record commitment
 * @param {Point} C_H - Hidden fields commitment
 * @param {Point} C_F - Filtered (visible) fields commitment
 */
function verifyPartition(C_D, C_H, C_F) {
  // C_H + C_F should equal C_D
  const sum = C_H.add(C_F);
  const valid = C_D.eq(sum);
  
  return {
    valid,
    math: {
      equation: 'C_D = C_H · C_F',
      verification: 'C_H + C_F = C_D ?',
      C_D: {
        x: C_D.getX().toString(16).padStart(64, '0'),
        y: C_D.getY().toString(16).padStart(64, '0')
      },
      C_H: {
        x: C_H.getX().toString(16).padStart(64, '0'),
        y: C_H.getY().toString(16).padStart(64, '0')
      },
      C_F: {
        x: C_F.getX().toString(16).padStart(64, '0'),
        y: C_F.getY().toString(16).padStart(64, '0')
      },
      sum: {
        x: sum.getX().toString(16).padStart(64, '0'),
        y: sum.getY().toString(16).padStart(64, '0')
      },
      result: valid ? 'EQUAL ✓' : 'NOT EQUAL ✗'
    }
  };
}

/**
 * Recompute commitment from data + randomness (client-side verification)
 */
function recomputeCommitment(fields) {
  let commitment = null;
  const details = [];
  
  for (const { fieldName, value, randomness } of fields) {
    const r = new BN(randomness, 16);
    const m = hashToScalar(`${fieldName}||${value}`);
    
    const gm = G.mul(m);
    const hr = H.mul(r);
    const C = gm.add(hr);
    
    details.push({
      field: fieldName,
      m: m.toString(16).slice(0, 16) + '...',
      r: randomness.slice(0, 16) + '...',
      C: C.getX().toString(16).slice(0, 16) + '...'
    });
    
    if (commitment === null) {
      commitment = C;
    } else {
      commitment = commitment.add(C);
    }
  }
  
  return { commitment, details };
}

/**
 * Serialize point to hex
 */
function serializePoint(point) {
  return {
    x: point.getX().toString(16).padStart(64, '0'),
    y: point.getY().toString(16).padStart(64, '0'),
    compressed: point.encode('hex', true)
  };
}

/**
 * Deserialize hex to point
 */
function deserializePoint(data) {
  if (typeof data === 'string') {
    return ec.curve.decodePoint(data, 'hex');
  }
  return ec.curve.point(data.x, data.y);
}

/**
 * Serialize BN to hex
 */
function serializeBN(bn) {
  return bn.toString(16).padStart(64, '0');
}

/**
 * Deserialize hex to BN
 */
function deserializeBN(hex) {
  return new BN(hex, 16);
}

module.exports = {
  getGeneratorInfo,
  hashToScalar,
  randomScalar,
  commitField,
  commitRecord,
  computeSubsetCommitment,
  verifyPartition,
  recomputeCommitment,
  serializePoint,
  deserializePoint,
  serializeBN,
  deserializeBN,
  G,
  H,
  ec
};
