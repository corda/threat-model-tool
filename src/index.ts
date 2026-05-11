// Main entry point for the Threat Model Tool TypeScript implementation

export { default as ThreatModel } from './models/ThreatModel.js';
export { default as Threat } from './models/Threat.js';
export { default as Asset } from './models/Asset.js';
export { default as Countermeasure } from './models/Countermeasure.js';
export { default as SecurityObjective } from './models/SecurityObjective.js';
export { default as Assumption } from './models/Assumption.js';
export { default as Scope } from './models/Scope.js';
export { default as REFID } from './models/REFID.js';
export { default as BaseThreatModelObject } from './models/BaseThreatModelObject.js';

export { default as CVSSHelper } from './utils/CVSSHelper.js';
export { default as TreeNode } from './utils/TreeNode.js';
export {
    loadHarFile,
    loadHar2SeqConfig,
    generate_puml_sequence,
    generate_indexHAR,
    create_indexHAR_file,
    generate_starter_HAR_config_yaml,
    create_starter_HAR_config_file,
    load_indexHAR_file,
    generateSequenceFromHar,
    generateMermaidFromHar,
    generatePlantUmlFromHar,
    buildSequenceFromHarFile,
    buildMermaidFromHarFile,
    buildPlantUmlFromHarFile,
    type Har2SeqConfig,
    type Har2SeqOptions,
    type SequenceFormat,
    type TrustBoundaryConfig,
    type CollapseParticipantConfig,
    type ParticipantPropertyConfig,
    type ParticipantPropertyValue,
    type HarFile,
    type HarIndexFile,
    type HarIndexEntry,
    type HarIndexLineRefs,
    type StarterConfigOptions,
} from './utils/HAR_2_TM_tool.js';

export { loadThreatModel, parseThreatModel } from './parser.js';

export { MarkdownRenderer, PlantUMLRenderer, PDFRenderer } from './renderers/index.js';
export { ReportGenerator } from './ReportGenerator.js';

export * from './types.js';

export { buildSingleTM, type BuildTMOptions } from './scripts/build-threat-model.js';
export { buildFullDirectory, type DirectoryBuildOptions } from './scripts/build-threat-model-directory.js';
export { verifyThreatModel, verifyDirectory } from './scripts/verify-threat-model.js';

// Jira integration
export {
    JiraClient,
    JiraProjectIssueType,
    JiraFields,
    buildReviewUrl,
    buildRiskReviewUrl,
    createJiraForThreat,
    threatDescription,
    riskDescription,
    treatmentPlan,
    threatDescriptionWiki,
    riskDescriptionWiki,
    threatDescriptionMarkdown,
    riskDescriptionMarkdown,
    threatDescriptionFormatted,
    riskDescriptionFormatted,
    mapCvssToImpact,
    riskRating,
    treatmentPlanDate,
    formatJiraDate,
} from './jira/index.js';
