import fs from 'fs';
import yaml from 'js-yaml';
import ThreatModel from './models/ThreatModel.js';
import type { ThreatModelData } from './types.js';

export function loadThreatModel(filePath: string): ThreatModel {
    const fileExtension = filePath.split('.').pop()?.toLowerCase();

    if (fileExtension === 'yaml' || fileExtension === 'yml') {
        return new ThreatModel(filePath);
    } else if (fileExtension === 'json') {
        return new ThreatModel(filePath);
    } else {
        throw new Error('Unsupported file format. Please provide a YAML or JSON file.');
    }
}

export function parseThreatModel(filePath: string): ThreatModelData {
    const fileExtension = filePath.split('.').pop()?.toLowerCase();
    let data: ThreatModelData;

    if (fileExtension === 'yaml' || fileExtension === 'yml') {
        data = loadYamlFile(filePath);
    } else if (fileExtension === 'json') {
        data = loadJsonFile(filePath);
    } else {
        throw new Error('Unsupported file format. Please provide a YAML or JSON file.');
    }

    return data;
}

function loadYamlFile(filePath: string): ThreatModelData {
    try {
        const fileContents = fs.readFileSync(filePath, 'utf8');
        return yaml.load(fileContents) as ThreatModelData;
    } catch (error) {
        throw new Error(`Error loading YAML file: ${(error as Error).message}`);
    }
}

function loadJsonFile(filePath: string): ThreatModelData {
    try {
        const fileContents = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(fileContents) as ThreatModelData;
    } catch (error) {
        throw new Error(`Error loading JSON file: ${(error as Error).message}`);
    }
}
