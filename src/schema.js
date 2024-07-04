const Arweave = require('arweave');
const WeaveDB = require('weavedb-sdk'); 

const arweave = new Arweave({
  host: 'arweave.net',
  port: 443,
  protocol: 'https'
});

const weaveDB = new WeaveDB(arweave);

const vulnerabilitySchema = {
  name: {
    type: String,
    required: true,
    unique: true
  },
  description: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Critical'],
    required: true
  },
  remediation: {
    type: String,
    required: true
  },
  references: [{
    type: String
  }]
};

const vulnerabilities = [
  {
    name: 'Reentrancy',
    description: 'Occurs when a function makes an external call to another untrusted contract before resolving any changes.',
    severity: 'Critical',
    remediation: 'Use a mutex to lock function execution or check-effects-interactions pattern.',
    references: ['https://example.com/reentrancy']
  },
  {
    name: 'Integer Overflow and Underflow',
    description: 'Occurs when arithmetic operations exceed the storage limits of their data types.',
    severity: 'High',
    remediation: 'Use SafeMath libraries to handle arithmetic operations.',
    references: ['https://example.com/integer-overflow-underflow']
  },
  {
    name: 'Access Control Issues',
    description: 'Improper access control can allow unauthorized users to perform restricted actions.',
    severity: 'Critical',
    remediation: 'Implement proper access control mechanisms and validate user permissions.',
    references: ['https://example.com/access-control']
  },
  {
    name: 'Uninitialized Storage Pointers',
    description: 'Uninitialized storage pointers can lead to unintentional data manipulation.',
    severity: 'High',
    remediation: 'Always initialize storage pointers before using them.',
    references: ['https://example.com/uninitialized-storage-pointers']
  },
  {
    name: 'Unrestricted Write to Storage',
    description: 'Allows unauthorized write access to storage, potentially leading to data corruption.',
    severity: 'Critical',
    remediation: 'Implement access control checks before allowing write operations.',
    references: ['https://example.com/unrestricted-write']
  },
  {
    name: 'Denial of Service',
    description: 'An attack that makes the contract unusable by consuming excessive gas or other resources.',
    severity: 'High',
    remediation: 'Optimize gas usage and validate inputs to prevent excessive resource consumption.',
    references: ['https://example.com/denial-of-service']
  },
  {
    name: 'Floating Pragma',
    description: 'Using a floating pragma can lead to inconsistent compiler behavior.',
    severity: 'Medium',
    remediation: 'Use a fixed compiler version for consistency.',
    references: ['https://example.com/floating-pragma']
  },
  {
    name: 'Self-destruct Function',
    description: 'Self-destructing a contract can lead to loss of funds and contract functionality.',
    severity: 'High',
    remediation: 'Avoid using self-destruct or restrict its access to authorized users.',
    references: ['https://example.com/self-destruct']
  },
  {
    name: 'Unchecked External Call',
    description: 'Failing to check the success of an external call can lead to unexpected behavior.',
    severity: 'High',
    remediation: 'Always check the return value of external calls.',
    references: ['https://example.com/unchecked-external-call']
  },
  {
    name: 'Timestamp Dependence',
    description: 'Using block timestamps for critical logic can be manipulated by miners.',
    severity: 'Medium',
    remediation: 'Avoid using timestamps for critical logic.',
    references: ['https://example.com/timestamp-dependence']
  },
  {
    name: 'Block Number Dependence',
    description: 'Using block numbers for critical logic can be manipulated by miners.',
    severity: 'Medium',
    remediation: 'Avoid using block numbers for critical logic.',
    references: ['https://example.com/block-number-dependence']
  },
  {
    name: 'Unprotected Suicide',
    description: 'Allows unauthorized users to destroy the contract.',
    severity: 'Critical',
    remediation: 'Restrict the suicide function to authorized users only.',
    references: ['https://example.com/unprotected-suicide']
  },
  {
    name: 'Signature Malleability',
    description: 'Allows signatures to be altered, potentially leading to unauthorized actions.',
    severity: 'High',
    remediation: 'Use EIP-2-compliant signatures to prevent malleability.',
    references: ['https://example.com/signature-malleability']
  },
  {
    name: 'Delegatecall Injection',
    description: 'Using delegatecall with user-controlled data can lead to code injection.',
    severity: 'Critical',
    remediation: 'Avoid using delegatecall with untrusted data.',
    references: ['https://example.com/delegatecall-injection']
  },
  {
    name: 'tx.origin Authentication',
    description: 'Using tx.origin for authentication can be exploited by malicious contracts.',
    severity: 'High',
    remediation: 'Use msg.sender for authentication instead of tx.origin.',
    references: ['https://example.com/tx-origin-authentication']
  },
  {
    name: 'Short Address Attack',
    description: 'Allows attackers to manipulate input data by providing shorter addresses.',
    severity: 'Medium',
    remediation: 'Validate the length of address inputs.',
    references: ['https://example.com/short-address-attack']
  },
  {
    name: 'Default Visibility',
    description: 'Functions with default visibility can be called by anyone.',
    severity: 'High',
    remediation: 'Specify the visibility of all functions explicitly.',
    references: ['https://example.com/default-visibility']
  },
  {
    name: 'Unhandled Exceptions',
    description: 'Failing to handle exceptions can lead to unintended behavior.',
    severity: 'High',
    remediation: 'Implement proper error handling for all operations.',
    references: ['https://example.com/unhandled-exceptions']
  },
  {
    name: 'Gas Limit and Loops',
    description: 'Using unbounded loops can exceed the gas limit, making functions unusable.',
    severity: 'High',
    remediation: 'Avoid unbounded loops and optimize gas usage.',
    references: ['https://example.com/gas-limit-loops']
  },
  {
    name: 'Force Sending Ether to Contracts',
    description: 'Contracts can be forced to accept ether, disrupting their logic.',
    severity: 'Medium',
    remediation: 'Implement a fallback function to handle unexpected ether.',
    references: ['https://example.com/force-sending-ether']
  }
];

async function createInitialVulnerabilities() {
  try {
    const result = await weaveDB.create('vulnerabilities', vulnerabilities);
    console.log('Initial vulnerabilities created in WeaveDB:', result);
  } catch (error) {
    console.error('Failed to create initial vulnerabilities in WeaveDB:', error);
  }
}

arweave.network.getInfo().then(() => {
  console.log('Connected to Arweave network');
  createInitialVulnerabilities();
}).catch(err => {
  console.error('Failed to connect to Arweave network:', err);
});

module.exports = vulnerabilities;
