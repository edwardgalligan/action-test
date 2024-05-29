#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import { Octokit } from '@octokit/core';

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN
});

const parseJson = (json) => {
  try {
    return JSON.parse(json);
  } catch (error) {
    console.error({ message: 'JSON Parse Error', error });
    return null;
  }
};

const artifactFromWssLibrary = (library) => {
  const artifact = {
    package: {
      ecosystem: 'other',
      name: library.name,
    },
    // ## Optional properties
    // vulnerable_version_range: '' | null,
    // patched_versions: '' | null,
    // vulnerable_functions: []
  };
  
  switch (library.type) {
    case 'JAVA_SCRIPT_LIBRARY':
      return {
        ...artifact,
      }
    case 'SOURCE_LIBRARY':
      return {
        ...artifact,
      }
    case 'MAVEN_ARTIFACT':
      return {
        ...artifact,
        package: {
          ...artifact.package,
          ecosystem: 'maven',
          name: library.groupId,
        },
        vulnerable_version_range: library.version
      };
    case 'NODE_PACKAGED_MODULE':
      return {
        ...artifact,
        package: {
          ...artifact.package,
          ecosystem: 'npm',
          name: library.groupId,
        },
        vulnerable_version_range: library.version
      };
    default:
      return artifact;
  }
};

const uploadSecurityAdvisory = advisory => octokit.request(
  'POST /repos/{owner}/{repo}/security-advisories', {
      ...advisory,
      owner: 'edwardgalligan',
      repo: 'action-test',
      headers: {
        'X-GitHub-Api-Version': '2022-11-28'
      }
  });

const ghAdvisoryFromWssVuln =
  ({
    name,
    // type,
    severity,
    scoreMetadataVector,
    // publishDate,
    // url,
    description,
    topFix,
  }, library) => ({
    // ## required properties
    summary: `[${name}]: ${topFix.fixResolution}`,
    description, // TODO: Add actionable advice to description
    severity,
    cvss_vector_string: scoreMetadataVector,
  });

const uploadSecurityAdvisoriesFromWssReport =
  wssReport => {
    const ghAdvisories = new Map();

    wssReport.libraries.forEach(library => {
      const artifact = artifactFromWssLibrary(library);
      library.vulnerabilities.forEach(wssVuln => {
        const ghAdvisory = ghAdvisories.get(wssVuln.name) || ghAdvisoryFromWssVuln(wssVuln, library);
        ghAdvisory.vulnerabilities.push(artifact);
        ghAdvisories.set(wssVuln.name, ghAdvisory);
      });
    });

    return Promise.all(
      ghAdvisories.values().map(uploadSecurityAdvisory)
    );
  };

readdirSync('./samples', { withFileTypes: true }).forEach(dirent => {
  if (dirent.isFile() && /\.scan_report\.json$/.test(dirent.name)) {
    const wssResultsJson = readFileSync(`./samples/${dirent.name}`);
    const wssResults = parseJson(wssResultsJson);
    uploadSecurityAdvisoriesFromWssReport(wssResults);
  }
});
