import { readdirSync, readFileSync } from 'node:fs';
import { Octokit } from '@octokit/core';

console.log('Running upload-mend-security-advisories.js');

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

const uploadSecurityAdvisory = advisory => {
  console.log('Uploading security advisory:', advisory.summary);
  return octokit.request(
  'POST /repos/{owner}/{repo}/security-advisories', {
      ...advisory,
      owner: 'edwardgalligan',
      repo: 'action-test',
      headers: {
        'X-GitHub-Api-Version': '2022-11-28'
      }
  })
  .then(r => console.log('Advisory uploaded: ', advisory.summary, r))
  .catch(e => console.error('Advisory upload failed:', advisory.summary, e));
};

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
    vulnerabilities: [],
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

console.log('reading dir samples');
readdirSync('./samples', { withFileTypes: true }).forEach(dirent => {
  console.log('reading dir "samples:', dirent);
  if (dirent.isFile() && /-scan_report\.json$/.test(dirent.name)) {
    const wssResultsJson = readFileSync(`./samples/${dirent.name}`);
    const wssResults = parseJson(wssResultsJson);
    uploadSecurityAdvisoriesFromWssReport(wssResults);
  }
});
