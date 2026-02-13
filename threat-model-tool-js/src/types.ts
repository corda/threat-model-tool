// Type definitions for Threat Model

export interface REFID {
  REFID: string;
}

export interface SecurityObjective {
  ID: string;
  title: string;
  description?: string;
  group?: string;
}

export interface Attacker {
  ID: string;
  description?: string;
  inScope?: boolean;
}

export interface Asset {
  ID: string;
  title: string;
  description?: string;
  type?: 'Data' | 'Service' | 'Hardware' | 'Software' | 'Network' | 'Physical';
}

export interface Assumption {
  ID: string;
  description: string;
}

export interface CVSSInfo {
  vector: string;
  score?: number;
  severity?: string;
}

export interface Countermeasure {
  ID: string;
  title: string;
  description?: string;
  inPlace?: boolean;
  status?: 'Planned' | 'InProgress' | 'Implemented' | 'NotApplicable';
}

export interface Threat {
  ID: string;
  title: string;
  attack: string;
  threatType: string;
  impactDesc?: string;
  impactedSecObj?: REFID[];
  attackers?: REFID[];
  CVSS?: CVSSInfo;
  fullyMitigated?: boolean;
  countermeasures?: Countermeasure[];
}

export interface Scope {
  description?: string;
  securityObjectives?: SecurityObjective[];
  attackers?: Attacker[];
  assets?: Asset[];
  assumptions?: Assumption[];
}

export interface ThreatModelData {
  ID: string;
  schemaVersion: number;
  title: string;
  version: string | number;
  authors?: string;
  scope?: Scope;
  analysis?: string;
  threats?: Threat[];
}

export type ThreatModelObjectType = 
  | 'ThreatModel'
  | 'Threat'
  | 'Countermeasure'
  | 'SecurityObjective'
  | 'Asset'
  | 'Attacker'
  | 'Assumption';
