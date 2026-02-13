import fs from 'fs';
import yaml from 'js-yaml';
import { ThreatModel } from './models/ThreatModel';

export function loadThreatModel(filePath) {
    const fileExtension = filePath.split('.').pop();
    let data;

    if (fileExtension === 'yaml' || fileExtension === 'yml') {
        data = loadYamlFile(filePath);
    } else if (fileExtension === 'json') {
        data = loadJsonFile(filePath);
    } else {
        throw new Error('Unsupported file format. Please provide a YAML or JSON file.');
    }

    return new ThreatModel(data);
}

function loadYamlFile(filePath) {
    try {
        const fileContents = fs.readFileSync(filePath, 'utf8');
        return yaml.load(fileContents);
    } catch (error) {
        throw new Error(`Error loading YAML file: ${error.message}`);
    }
}

function loadJsonFile(filePath) {
    try {
        const fileContents = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(fileContents);
    } catch (error) {
        throw new Error(`Error loading JSON file: ${error.message}`);
    }
}