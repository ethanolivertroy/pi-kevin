import type {
  CisControl,
  CisControlSummary,
  ControlDetailsResult,
  ControlMappingResult,
  ControlSummary,
  CveDetails,
  KevRecord,
  ListControlsResult,
  SecurityControl,
} from "./types.js";

const NIST_CONTROLS: Record<string, SecurityControl> = {
  "SI-2": {
    id: "SI-2",
    family: "System and Information Integrity",
    name: "Flaw Remediation",
    description: "Identify, report, and correct system flaws. Install security-relevant software updates within organization-defined time period.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "RA-5": {
    id: "RA-5",
    family: "Risk Assessment",
    name: "Vulnerability Monitoring and Scanning",
    description: "Monitor and scan for vulnerabilities in the system and hosted applications. Employ vulnerability monitoring tools using CVE, CWE, and NVD databases.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "CM-6": {
    id: "CM-6",
    family: "Configuration Management",
    name: "Configuration Settings",
    description: "Establish and document configuration settings for system components using security configuration checklists.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "CM-8": {
    id: "CM-8",
    family: "Configuration Management",
    name: "System Component Inventory",
    description: "Develop and document an inventory of system components that accurately reflects the system and is consistent with the authorization boundary.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "CA-7": {
    id: "CA-7",
    family: "Assessment, Authorization, and Monitoring",
    name: "Continuous Monitoring",
    description: "Develop a continuous monitoring strategy and implement a continuous monitoring program that includes ongoing security and privacy control assessments.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "IR-4": {
    id: "IR-4",
    family: "Incident Response",
    name: "Incident Handling",
    description: "Implement an incident handling capability for incidents that includes preparation, detection, analysis, containment, eradication, and recovery.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "IR-6": {
    id: "IR-6",
    family: "Incident Response",
    name: "Incident Reporting",
    description: "Require personnel to report suspected incidents to the organizational incident response capability within organization-defined time period.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "SC-7": {
    id: "SC-7",
    family: "System and Communications Protection",
    name: "Boundary Protection",
    description: "Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces within the system.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "SI-3": {
    id: "SI-3",
    family: "System and Information Integrity",
    name: "Malicious Code Protection",
    description: "Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "SI-4": {
    id: "SI-4",
    family: "System and Information Integrity",
    name: "System Monitoring",
    description: "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized local, network, and remote connections.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "SI-10": {
    id: "SI-10",
    family: "System and Information Integrity",
    name: "Information Input Validation",
    description: "Check the validity of information inputs to the system to verify inputs match specified definitions for format and content.",
    priority: "P1",
    baseline: ["Moderate", "High"],
    framework: "NIST 800-53",
  },
  "AC-3": {
    id: "AC-3",
    family: "Access Control",
    name: "Access Enforcement",
    description: "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "AC-6": {
    id: "AC-6",
    family: "Access Control",
    name: "Least Privilege",
    description: "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned organizational tasks.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "IA-2": {
    id: "IA-2",
    family: "Identification and Authentication",
    name: "Identification and Authentication (Organizational Users)",
    description: "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "IA-5": {
    id: "IA-5",
    family: "Identification and Authentication",
    name: "Authenticator Management",
    description: "Manage system authenticators by verifying identity before initial distribution, establishing initial content, and protecting against unauthorized disclosure.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "AU-6": {
    id: "AU-6",
    family: "Audit and Accountability",
    name: "Audit Record Review, Analysis, and Reporting",
    description: "Review and analyze system audit records for indications of inappropriate or unusual activity and report findings.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "CP-9": {
    id: "CP-9",
    family: "Contingency Planning",
    name: "System Backup",
    description: "Conduct backups of user-level and system-level information contained in the system on a defined frequency.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
  "CP-10": {
    id: "CP-10",
    family: "Contingency Planning",
    name: "System Recovery and Reconstitution",
    description: "Provide for the recovery and reconstitution of the system to a known state within organization-defined time period.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "NIST 800-53",
  },
};

const FEDRAMP_CONTROLS: Record<string, SecurityControl> = {
  "SI-2": {
    id: "SI-2",
    family: "System and Information Integrity",
    name: "Flaw Remediation",
    description: "High-impact vulnerabilities must be remediated within 30 days. Critical vulnerabilities within 15 days for FedRAMP systems.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "FedRAMP",
  },
  "RA-5": {
    id: "RA-5",
    family: "Risk Assessment",
    name: "Vulnerability Monitoring and Scanning",
    description: "Perform vulnerability scans at least monthly and within 72 hours of new vulnerability disclosure for FedRAMP systems.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "FedRAMP",
  },
  "IR-4": {
    id: "IR-4",
    family: "Incident Response",
    name: "Incident Handling",
    description: "Report incidents to US-CERT within 1 hour of identification for FedRAMP systems.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "FedRAMP",
  },
  "CA-7": {
    id: "CA-7",
    family: "Assessment, Authorization, and Monitoring",
    name: "Continuous Monitoring",
    description: "Implement continuous monitoring per FedRAMP ConMon requirements including monthly vulnerability scans and annual assessments.",
    priority: "P1",
    baseline: ["Low", "Moderate", "High"],
    framework: "FedRAMP",
  },
};

const CWE_TO_CONTROL_MAPPING: Record<string, string[]> = {
  "CWE-78": ["SI-2", "SI-10", "SC-7"],
  "CWE-79": ["SI-2", "SI-10"],
  "CWE-89": ["SI-2", "SI-10"],
  "CWE-94": ["SI-2", "SI-10", "SC-7"],
  "CWE-77": ["SI-2", "SI-10", "SC-7"],
  "CWE-287": ["IA-2", "IA-5", "SI-2"],
  "CWE-306": ["AC-3", "AC-6", "SI-2"],
  "CWE-862": ["AC-3", "AC-6", "SI-2"],
  "CWE-863": ["AC-3", "AC-6", "SI-2"],
  "CWE-269": ["AC-6", "SI-2"],
  "CWE-120": ["SI-2", "SI-4"],
  "CWE-122": ["SI-2", "SI-4"],
  "CWE-787": ["SI-2", "SI-4"],
  "CWE-416": ["SI-2", "SI-4"],
  "CWE-125": ["SI-2", "SI-4"],
  "CWE-22": ["SI-2", "AC-3", "AC-6"],
  "CWE-434": ["SI-2", "AC-3", "SI-10"],
  "CWE-502": ["SI-2", "SI-10", "SC-7"],
  "CWE-200": ["SI-2", "AC-3", "AU-6"],
  "CWE-532": ["SI-2", "AU-6"],
};

const CIS_CONTROLS: Record<string, CisControl> = {
  "1.1": { id: "1.1", title: "Establish and Maintain Detailed Enterprise Asset Inventory", description: "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Identify" },
  "1.2": { id: "1.2", title: "Address Unauthorized Assets", description: "Ensure that a process exists to address unauthorized assets on a weekly basis.", ig1: true, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Respond" },
  "2.1": { id: "2.1", title: "Establish and Maintain a Software Inventory", description: "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Identify" },
  "2.2": { id: "2.2", title: "Ensure Authorized Software is Currently Supported", description: "Ensure that only currently supported software is designated as authorized.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Identify" },
  "2.3": { id: "2.3", title: "Address Unauthorized Software", description: "Ensure that unauthorized software is either removed or the inventory is updated in a timely manner.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Respond" },
  "3.1": { id: "3.1", title: "Establish and Maintain a Data Management Process", description: "Establish and maintain a data management process including data sensitivity levels.", ig1: true, ig2: true, ig3: true, assetType: "Data", securityFunction: "Identify" },
  "3.4": { id: "3.4", title: "Enforce Data Retention", description: "Retain data according to the enterprise's data management process.", ig1: true, ig2: true, ig3: true, assetType: "Data", securityFunction: "Protect" },
  "4.1": { id: "4.1", title: "Establish and Maintain a Secure Configuration Process", description: "Establish and maintain a secure configuration process for enterprise assets and software.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Protect" },
  "4.7": { id: "4.7", title: "Manage Default Accounts on Enterprise Assets and Software", description: "Manage default accounts on enterprise assets and software.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "5.1": { id: "5.1", title: "Establish and Maintain an Inventory of Accounts", description: "Establish and maintain an inventory of all accounts managed in the enterprise.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Identify" },
  "5.3": { id: "5.3", title: "Disable Dormant Accounts", description: "Delete or disable any dormant accounts after a period of 45 days of inactivity.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "5.4": { id: "5.4", title: "Restrict Administrator Privileges to Dedicated Administrator Accounts", description: "Restrict administrator privileges to dedicated administrator accounts on enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "6.1": { id: "6.1", title: "Establish an Access Granting Process", description: "Establish and follow a process for granting access to enterprise assets and software.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "6.2": { id: "6.2", title: "Establish an Access Revoking Process", description: "Establish and follow a process for revoking access to enterprise assets and software.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "6.5": { id: "6.5", title: "Require MFA for Administrative Access", description: "Require MFA for all administrative access accounts.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "7.1": { id: "7.1", title: "Establish and Maintain a Vulnerability Management Process", description: "Establish and maintain a documented vulnerability management process for enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Identify" },
  "7.2": { id: "7.2", title: "Establish and Maintain a Remediation Process", description: "Establish and maintain a risk-based remediation strategy documented in a remediation process.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Respond" },
  "7.3": { id: "7.3", title: "Perform Automated Operating System Patch Management", description: "Perform operating system updates on enterprise assets through automated patch management.", ig1: true, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Protect" },
  "7.4": { id: "7.4", title: "Perform Automated Application Patch Management", description: "Perform application updates on enterprise assets through automated patch management.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Protect" },
  "7.5": { id: "7.5", title: "Perform Automated Vulnerability Scans of Internal Enterprise Assets", description: "Perform automated vulnerability scans of internal enterprise assets on a quarterly basis.", ig1: false, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Detect" },
  "7.6": { id: "7.6", title: "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets", description: "Perform automated vulnerability scans of externally-exposed enterprise assets.", ig1: false, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Detect" },
  "7.7": { id: "7.7", title: "Remediate Detected Vulnerabilities", description: "Remediate detected vulnerabilities in software through processes and tooling on a monthly basis.", ig1: false, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Respond" },
  "8.1": { id: "8.1", title: "Establish and Maintain an Audit Log Management Process", description: "Establish and maintain an audit log management process that defines logging requirements.", ig1: true, ig2: true, ig3: true, assetType: "Network", securityFunction: "Detect" },
  "8.2": { id: "8.2", title: "Collect Audit Logs", description: "Collect audit logs from enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Network", securityFunction: "Detect" },
  "9.1": { id: "9.1", title: "Ensure Use of Only Fully Supported Browsers and Email Clients", description: "Ensure only fully supported browsers and email clients are allowed to execute.", ig1: true, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Protect" },
  "10.1": { id: "10.1", title: "Deploy and Maintain Anti-Malware Software", description: "Deploy and maintain anti-malware software on all enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Protect" },
  "10.2": { id: "10.2", title: "Configure Automatic Anti-Malware Signature Updates", description: "Configure automatic updates for anti-malware signature files.", ig1: true, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Protect" },
  "10.7": { id: "10.7", title: "Use Behavior-Based Anti-Malware Software", description: "Use behavior-based anti-malware software.", ig1: false, ig2: true, ig3: true, assetType: "Devices", securityFunction: "Detect" },
  "11.1": { id: "11.1", title: "Establish and Maintain a Data Recovery Process", description: "Establish and maintain a data recovery process including scope of recovery activities.", ig1: true, ig2: true, ig3: true, assetType: "Data", securityFunction: "Recover" },
  "11.2": { id: "11.2", title: "Perform Automated Backups", description: "Perform automated backups of in-scope enterprise assets.", ig1: true, ig2: true, ig3: true, assetType: "Data", securityFunction: "Recover" },
  "11.4": { id: "11.4", title: "Establish and Maintain an Isolated Instance of Recovery Data", description: "Establish and maintain an isolated instance of recovery data using offline or cloud storage.", ig1: true, ig2: true, ig3: true, assetType: "Data", securityFunction: "Recover" },
  "12.1": { id: "12.1", title: "Ensure Network Infrastructure is Up-to-Date", description: "Ensure network infrastructure is kept up-to-date.", ig1: true, ig2: true, ig3: true, assetType: "Network", securityFunction: "Protect" },
  "13.1": { id: "13.1", title: "Centralize Security Event Alerting", description: "Centralize security event alerting across enterprise assets.", ig1: false, ig2: true, ig3: true, assetType: "Network", securityFunction: "Detect" },
  "14.1": { id: "14.1", title: "Establish and Maintain a Security Awareness Program", description: "Establish and maintain a security awareness program.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "14.2": { id: "14.2", title: "Train Workforce Members to Recognize Social Engineering Attacks", description: "Train workforce members to recognize social engineering attacks.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Protect" },
  "15.1": { id: "15.1", title: "Establish and Maintain an Inventory of Service Providers", description: "Establish and maintain an inventory of service providers.", ig1: true, ig2: true, ig3: true, assetType: "Network", securityFunction: "Identify" },
  "16.1": { id: "16.1", title: "Establish and Maintain a Secure Application Development Process", description: "Establish and maintain a secure application development process.", ig1: false, ig2: true, ig3: true, assetType: "Applications", securityFunction: "Protect" },
  "17.1": { id: "17.1", title: "Designate Personnel to Manage Incident Handling", description: "Designate one key person, and at least one backup, to manage incident handling.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Respond" },
  "17.2": { id: "17.2", title: "Establish and Maintain Contact Information for Reporting Security Incidents", description: "Establish and maintain contact information for reporting security incidents.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Respond" },
  "17.3": { id: "17.3", title: "Establish and Maintain an Enterprise Process for Reporting Incidents", description: "Establish and maintain an enterprise process for the workforce to report security incidents.", ig1: true, ig2: true, ig3: true, assetType: "Users", securityFunction: "Respond" },
  "18.1": { id: "18.1", title: "Establish and Maintain a Penetration Testing Program", description: "Establish and maintain a penetration testing program appropriate to the size and complexity.", ig1: false, ig2: true, ig3: true, assetType: "Network", securityFunction: "Identify" },
};

const CWE_TO_CIS_MAPPING: Record<string, string[]> = {
  "CWE-78": ["7.1", "7.2", "7.3", "7.4", "4.1", "16.1"],
  "CWE-79": ["7.1", "7.2", "9.1", "16.1"],
  "CWE-89": ["7.1", "7.2", "16.1", "4.1"],
  "CWE-94": ["7.1", "7.2", "7.4", "16.1"],
  "CWE-502": ["7.1", "7.2", "16.1", "4.1"],
  "CWE-287": ["5.1", "5.3", "5.4", "6.1", "6.2", "6.5"],
  "CWE-269": ["5.4", "6.1", "6.2"],
  "CWE-352": ["9.1", "16.1"],
  "CWE-119": ["7.1", "7.2", "7.3", "7.4", "2.2"],
  "CWE-787": ["7.1", "7.2", "7.3", "7.4"],
  "CWE-416": ["7.1", "7.2", "7.3", "7.4"],
  "CWE-200": ["3.1", "3.4", "8.1", "8.2"],
  "CWE-434": ["4.1", "9.1", "16.1"],
  "CWE-611": ["4.1", "16.1"],
  "CWE-918": ["4.1", "12.1", "16.1"],
};

function normalizeCwe(cwe: string): string {
  const normalized = cwe.trim().toUpperCase().replace(/^CWE-/, "");
  return normalized ? `CWE-${normalized}` : "";
}

function calculateConfidence(record: KevRecord | CveDetails, controlCount: number): number {
  let confidence = 0.5;
  const cwes = record.cwes ?? [];
  const epssScore = "epssScore" in record ? (record.epssScore ?? 0) : ((record as KevRecord).epss?.score ?? 0);

  if (cwes.length > 0) confidence += 0.2;
  if (cwes.length > 2) confidence += 0.1;
  if (epssScore > 0) confidence += 0.1;
  if (controlCount >= 3) confidence += 0.1;
  return Math.min(1, confidence);
}

function toControlSummary(control: SecurityControl): ControlSummary {
  return {
    id: control.id,
    name: control.name,
    family: control.family,
    priority: control.priority,
    baseline: control.baseline,
    description: control.description,
  };
}

function toCisSummary(control: CisControl): CisControlSummary {
  return {
    id: control.id,
    title: control.title,
    implementationGroup: control.ig1 ? "IG1" : control.ig2 ? "IG2" : "IG3",
    securityFunction: control.securityFunction,
    assetType: control.assetType,
  };
}

export function mapCveToControls(details: CveDetails, frameworkRaw: string | undefined): ControlMappingResult {
  const framework = (frameworkRaw ?? "nist").toLowerCase();
  if (!details.found) {
    return { cveId: details.cveId, framework, found: false, rationale: "CVE not found in KEV catalog", confidence: 0 };
  }

  if (framework === "cis") {
    const controlIds = new Set<string>(["7.1", "7.2", "7.3", "7.4", "1.1", "2.1"]);
    const rationale: string[] = ["KEV entry requires vulnerability management (7.1, 7.2) and patch management (7.3, 7.4)"];

    for (const cwe of details.cwes ?? []) {
      const key = normalizeCwe(cwe);
      for (const id of CWE_TO_CIS_MAPPING[key] ?? []) controlIds.add(id);
      if (key && CWE_TO_CIS_MAPPING[key]) rationale.push(`${key} maps to additional CIS controls`);
    }

    if (details.ransomwareUse) {
      for (const id of ["10.1", "10.2", "11.1", "11.2", "11.4", "17.1", "17.2", "17.3"]) controlIds.add(id);
      rationale.push("Ransomware association requires malware defenses, recovery, and incident response controls");
    }

    const epss = details.epssScore ?? 0;
    if (epss >= 0.7) {
      for (const id of ["8.1", "8.2", "13.1"]) controlIds.add(id);
      rationale.push(`High EPSS score (${Math.round(epss * 100)}%) requires enhanced logging and monitoring`);
    } else if (epss >= 0.3) {
      for (const id of ["8.1", "8.2"]) controlIds.add(id);
      rationale.push(`Moderate EPSS score (${Math.round(epss * 100)}%) suggests audit logging`);
    }

    const cisControls = [...controlIds].map((id) => CIS_CONTROLS[id]).filter(Boolean);
    return {
      cveId: details.cveId,
      framework: "cis",
      cisControls: cisControls.map(toCisSummary),
      rationale: rationale.join("; "),
      confidence: calculateConfidence(details, cisControls.length),
      found: true,
    };
  }

  const source = framework === "fedramp" ? FEDRAMP_CONTROLS : NIST_CONTROLS;
  const controlIds = new Set<string>(["SI-2", "RA-5", "CM-8", "CA-7"]);
  const rationale: string[] = ["KEV entry requires vulnerability scanning (RA-5) and flaw remediation (SI-2)"];

  for (const cwe of details.cwes ?? []) {
    const key = normalizeCwe(cwe);
    for (const id of CWE_TO_CONTROL_MAPPING[key] ?? []) controlIds.add(id);
    if (key && CWE_TO_CONTROL_MAPPING[key]) rationale.push(`${key} maps to additional controls`);
  }

  if (details.ransomwareUse) {
    for (const id of ["IR-4", "IR-6", "SI-3", "SC-7", "CP-9", "CP-10"]) controlIds.add(id);
    rationale.push("Ransomware association requires incident response, malware protection, and backup recovery controls");
  }

  const epss = details.epssScore ?? 0;
  if (epss >= 0.7) {
    controlIds.add("SI-4");
    controlIds.add("AU-6");
    rationale.push(`High EPSS score (${Math.round(epss * 100)}%) requires enhanced monitoring and audit review`);
  } else if (epss >= 0.3) {
    controlIds.add("SI-4");
    rationale.push(`Moderate EPSS score (${Math.round(epss * 100)}%) suggests system monitoring`);
  }

  const controls = [...controlIds]
    .map((id) => source[id] ?? NIST_CONTROLS[id])
    .filter((control): control is SecurityControl => Boolean(control));

  return {
    cveId: details.cveId,
    framework,
    controls: controls.map(toControlSummary),
    rationale: rationale.join("; "),
    confidence: calculateConfidence(details, controls.length),
    found: true,
  };
}

export function getControlDetails(controlIdRaw: string, frameworkRaw: string | undefined): ControlDetailsResult {
  const framework = (frameworkRaw ?? "nist").toLowerCase();
  const controlId = controlIdRaw.trim().toUpperCase();
  if (framework === "cis") {
    const cisControl = CIS_CONTROLS[controlIdRaw.trim()];
    return cisControl ? { found: true, cisControl } : { found: false };
  }

  const source = framework === "fedramp" ? FEDRAMP_CONTROLS : NIST_CONTROLS;
  const control = source[controlId] ?? NIST_CONTROLS[controlId];
  return control ? { found: true, control } : { found: false };
}

export function listControls(params: { family?: string; framework?: string; implementationGroup?: number }): ListControlsResult {
  const framework = (params.framework ?? "nist").toLowerCase();
  if (framework === "cis") {
    const securityFunction = params.family?.trim().toLowerCase();
    const implementationGroup = params.implementationGroup ?? 0;
    const cisControls = Object.values(CIS_CONTROLS).filter((control) => {
      if (implementationGroup === 1 && !control.ig1) return false;
      if (implementationGroup === 2 && !control.ig2) return false;
      if (implementationGroup === 3 && !control.ig3) return false;
      if (securityFunction && control.securityFunction.toLowerCase() !== securityFunction) return false;
      return true;
    });
    return { count: cisControls.length, cisControls };
  }

  const family = params.family?.trim().toLowerCase();
  const source = framework === "fedramp" ? FEDRAMP_CONTROLS : NIST_CONTROLS;
  const controls = Object.values(source).filter((control) => {
    if (!family) return true;
    return control.family.toLowerCase().includes(family) || control.name.toLowerCase().includes(family);
  });
  return { count: controls.length, controls };
}
