const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Arweave = require('arweave');
const WeaveDB = require('weavedb-sdk'); 
const vulnerabilities = require('./schema');

const app = express();
const port = 3000;

app.use(bodyParser.json());


const upload = multer({ dest: 'uploads/' });

const arweave = new Arweave({
  host: 'arweave.net',
  port: 443,
  protocol: 'https'
});

const weaveDB = new WeaveDB(arweave);

function analyzeCodeForVulnerabilities(code) {
  return vulnerabilities.filter(v => code.includes(v.name));
}

app.post('/upload', upload.single('file'), (req, res) => {
  const filePath = path.join(__dirname, req.file.path);
  fs.readFile(filePath, 'utf8', async (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read the uploaded file' });
    }

    const detectedVulnerabilities = analyzeCodeForVulnerabilities(data);

    res.status(200).json({ vulnerabilities: detectedVulnerabilities });

    try {
      await weaveDB.create('vulnerabilities', detectedVulnerabilities);
      console.log('Vulnerabilities saved to WeaveDB');
    } catch (error) {
      console.error('Failed to save vulnerabilities to WeaveDB:', error);
    }

    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Failed to delete the uploaded file:', err);
      }
    });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
