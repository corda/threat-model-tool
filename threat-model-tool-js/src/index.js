// src/index.js

import { ThreatModel } from './models/ThreatModel';
import { parseThreatModel } from './parser';

const initializeThreatModel = (filePath) => {
    try {
        const threatModelData = parseThreatModel(filePath);
        const threatModel = new ThreatModel(threatModelData);
        console.log('Threat Model initialized successfully:', threatModel);
    } catch (error) {
        console.error('Error initializing Threat Model:', error);
    }
};

// Example usage
const filePath = './path/to/threat-model.yaml'; // Update with the actual path to your YAML file
initializeThreatModel(filePath);