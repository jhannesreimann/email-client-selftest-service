# Network Security in Practice 2025 - Team 2
## TLS Project Repository

**Team Members:** Sofya & Jhannes  
**Weekly Meeting:** Monday: 13:30-14:00  
**Supervisors:** Feng (G2.E-25) and Pejman (G2.E-35)

---

## 📋 Repository Structure

This repository is organized to facilitate project management, documentation, and deliverable tracking throughout the NSIP course. Each directory serves a specific purpose in our workflow.

### 📂 `00-deliverables/`
**Purpose:** Final and intermediate deliverables for submission

**Contents:**
- Presentation slides (Lightning Talk, Phase I, Phase II)
- Final technical report
- Demo materials and recordings
- Implementation packages
- Any submission-ready materials

**Key Dates:**
- 08.12.2025: Lightning Talk (without slides)
- 12.01.2026: Intermediate Presentation (Phase I)
- 16.02.2026: Final Presentation (Phase II)
- 29.03.2026: Final Deliverables Submission Deadline

---

### 📂 `10-planning/`
**Purpose:** Project planning, task management, and milestone tracking

**Contents:**
- Project timeline and Gantt charts
- Task assignments and responsibilities
- Meeting schedules and agendas
- Risk assessment and mitigation strategies
- Research questions and objectives
- Implementation roadmap

**Note:** Regular updates to planning documents demonstrate active project management (evaluated as part of the Technical Report - 20%)

---

### 📂 `20-protocol/`
**Purpose:** Meeting notes, progress documentation, and activity logs

**Contents:**
- Weekly meeting notes (with supervisors)
- Internal team meeting protocols
- Progress reports and status updates
- Decision logs and rationale
- Q&A documentation from supervisor meetings
- Issue tracking and resolution notes

**Note:** Documentation of progress is one of the measurements to evaluate seminar activities

---

### 📂 `30-summary/`
**Purpose:** Summaries of research findings, literature reviews, and technical insights

**Contents:**
- Literature review summaries
- Research paper analyses
- Technical concept summaries (TLS protocols, cryptography, implementations)
- Experiment results and observations
- Best practices and lessons learned
- Architecture and design documentation

---

### 📂 `40-references/`
**Purpose:** Bibliographic references and resource management

**Contents:**
- BibTeX file (`.bib`) for all references
- PDF copies of papers and articles
- Links to useful resources
- Citation notes and annotations
- Research materials organized by topic

**Reference Management:**
- Use [JabRef](http://www.jabref.org/) for managing references
- Follow proper citation formats (inproceedings for papers, article for journals, etc.)
- Name sources clearly for easy reference
- Document all external resources used in the project

---

### 📂 `50-implementation/`
**Purpose:** Practical implementation work, server setup, and attack scripts

**Contents:**
- **Server Setup:** Email server configurations (Postfix, Dovecot)
  - Multiple connection modes: I-TLS and O-TLS (STARTTLS)
  - Port configurations (993, 995, 465, 143, 110, 587)
- **MITM Scripts:** mitmproxy-based attack implementations
  - Test cases T1-T4 (STARTTLS downgrade attacks)
  - Certificate validation tests (C1-C4)
- **Client Testing:** Email client testing setup and results
  - Test configurations and logs
  - Vulnerability analysis documentation
- **Deployment:** VM setup, network configuration, Docker files

**Project Context:**
- Recreating research from "A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems" (NDSS 2025)
- Original code repositories:
  - https://github.com/tls-downgrade
  - https://github.com/tls-downgrade/email-security
  - https://github.com/tls-downgrade/tls-downgrade

**Note:** This directory directly contributes to the **Practice (Implementation)** evaluation component (10% in Phase I, 20% in Phase II)

---

## 📊 Evaluation Breakdown

### Intermediate (40%)
- **Gather Together Talk:** 10%
- **Presentation (research):** 20%
- **Practice (implementation):** 10%

### Final (40%)
- **Presentation (design + architecture + experiments + analysis):** 20%
- **Practice (implementation):** 20%

### Technical Report (20%)
- Project management, final deliverable, report, documentation

**Bonus:** Active participation, creative/innovative ideas, and successful implementations

---

## 🔗 Useful Resources

### Course Information
- [Administrative Repository](https://gitlab.hpi.de/seceng/studentspace/nsip-2025/administrative)
- [HPI Teaching Page - NSIP2025](https://hpi.de/meinel/lehrstuhl/team/senior-researcher/feng-cheng/teaching-activities/nsip2526.html)

### Writing Guidelines
- [Prof. Naumann's Scientific Writing Hints](https://hpi.de/naumann/people/felix-naumann/writing.html)
- [Prof. Polze's Thesis Writing Tips](https://osm.hpi.de/theses/tipps)

### Security Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Vulnerability Classification](https://www.owasp.org/index.php/Vulnerability_Classification_Mappings)
- [Splunk Security Research](https://research.splunk.com/detections/)
- [DetectionLab](https://detectionlab.network/)

### Top Security Conferences
- [ACM CCS](https://www.sigsac.org/ccs.html) - [DBLP](https://dblp.org/db/conf/ccs/index.html)
- [IEEE S&P](https://www.ieee-security.org/TC/SP-Index.html) - [DBLP](https://dblp.org/db/conf/sp/index.html)
- [USENIX Security](https://www.usenix.org/conferences/byname/108) - [DBLP](https://dblp.org/db/conf/uss/index.html)
- [NDSS](https://www.ndss-symposium.org/) - [DBLP](https://dblp.org/db/conf/ndss/index.html)
- [ACSAC](https://www.acsac.org/) - [DBLP](https://dblp.org/db/conf/acsac/index.html)

### Online Courses
- [Missing Semester](https://missing.csail.mit.edu/2020/) / [Hacker Tools](https://hacker-tools.github.io/course-overview/)
- [MIT Computer Systems Security](https://css.csail.mit.edu/6.858/2020/)

### Security Talks
- [CCC Media](https://media.ccc.de/)
- [Black Hat](https://www.youtube.com/c/BlackHatOfficialYT/) / [Archive](https://www.blackhat.com/html/bh-media-archives/bh-multi-media-archives.html)
- [DEF CON](https://media.defcon.org/)

---

## 🎯 Project Topic: TLS & Email Security

### Research Focus
**Email Auto-Detect Vulnerabilities and TLS Downgrade Attacks**

Our project recreates and extends the research from the NDSS 2025 paper "A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems." We investigate security vulnerabilities in email clients' auto-detect features that allow attackers to strip TLS encryption and capture credentials in plaintext.

### Key Research Questions
1. Are current (2025/2026) email client versions still vulnerable to STARTTLS downgrade attacks?
2. How do different clients implement auto-detect, and which implementation patterns are most vulnerable?
3. What certificate validation weaknesses exist in popular email clients?
4. How do real-world setup guides (e.g., HPI documentation) impact user security?

### Phase I Focus (Current)
- ✅ Literature review and paper analysis
- 🔄 Email server testbed setup (Postfix + Dovecot)
- 🔄 MITM framework development (mitmproxy)
- 📋 Initial test case implementation (T1-T4)

### Phase II Focus (Upcoming)
- Complete client testing across multiple platforms
- Certificate validation experiments (C1-C4)
- Real-world setup guide analysis
- Experiments, measurements, and security analysis
- Comparison with original paper findings

---

## 📝 Working Practices

1. **Document Everything:** Keep detailed notes in `20-protocol/` for all meetings and decisions
2. **Update Regularly:** Maintain progress documentation to demonstrate ongoing work
3. **Organize References:** Use `40-references/` systematically with proper citations
4. **Plan Iteratively:** Update `10-planning/` as the project evolves
5. **Track Implementation:** Document all setup steps, configurations, and test results in `50-implementation/`
6. **Prepare Deliverables Early:** Use `00-deliverables/` to stage materials before deadlines

---
