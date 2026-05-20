/* ----------------------------------------------------
   Nessus Nexus Application Logic
   High-Fidelity XML Parser, Merger & Report Engine
------------------------------------------------------- */

(function () {
    // Default ignore list matching the original Java project's notNeededVulnerabilities.txt
    const DEFAULT_IGNORED_VULNERABILITIES = [
        "SSL Self-Signed Certificate",
        "SNMP 'GETBULK' Reflection DDoS",
        "SSL Certificate Signed Using Weak Hashing Algorithm",
        "OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Session Resume Ciphersuite Downgrade Issue"
    ];

    // Core State
    const state = {
        files: [],             // Loaded .nessus files: { name, size, rawText }
        ignoredVulns: [...DEFAULT_IGNORED_VULNERABILITIES],
        minCvss: 0.0,
        showIP: true,
        showMAC: false,
        showNetBios: false,
        showNA: true,
        
        // Parsed results
        vulnerabilities: [],   // Aggregated, sanitized, sorted vulnerability objects
        hosts: [],             // Parsed hosts with nested vulnerabilities list
        reportName: "Unified Report",
        
        // Active view filters
        searchQuery: "",
        severityFilter: "all"
    };

    // DOM Elements
    const elements = {
        dropZone: document.getElementById('drop-zone'),
        fileInput: document.getElementById('file-input'),
        loadedFilesContainer: document.getElementById('loaded-files-container'),
        fileCount: document.getElementById('file-count'),
        fileList: document.getElementById('file-list'),
        
        // Settings elements
        chkIp: document.getElementById('chk-ip'),
        chkMac: document.getElementById('chk-mac'),
        chkNetbios: document.getElementById('chk-netbios'),
        chkNa: document.getElementById('chk-na'),
        cvssThreshold: document.getElementById('cvss-threshold'),
        cvssVal: document.getElementById('cvss-val'),
        ignoredInput: document.getElementById('ignored-input'),
        btnAddIgnored: document.getElementById('btn-add-ignored'),
        ignoredTagsWrapper: document.getElementById('ignored-tags-wrapper'),
        btnResetIgnored: document.getElementById('btn-reset-ignored'),
        
        // View elements
        emptyState: document.getElementById('empty-state'),
        dashboardActive: document.getElementById('dashboard-active'),
        statHosts: document.getElementById('stat-hosts'),
        statVulns: document.getElementById('stat-vulns'),
        statScans: document.getElementById('stat-scans'),
        
        // Severity metrics
        countCritical: document.getElementById('count-critical'),
        countHigh: document.getElementById('count-high'),
        countMedium: document.getElementById('count-medium'),
        countLow: document.getElementById('count-low'),
        barCritical: document.getElementById('bar-critical'),
        barHigh: document.getElementById('bar-high'),
        barMedium: document.getElementById('bar-medium'),
        barLow: document.getElementById('bar-low'),
        
        // Exporter Buttons
        btnDlMini: document.getElementById('btn-dl-mini'),
        btnDlDetailed: document.getElementById('btn-dl-detailed'),
        btnDlHost: document.getElementById('btn-dl-host'),
        btnMergeScans: document.getElementById('btn-merge-scans'),
        
        // Explorer Table
        explorerSearch: document.getElementById('explorer-search'),
        explorerTableBody: document.getElementById('explorer-table-body'),
        filterPills: document.querySelectorAll('.filter-pill'),
        
        // Tabs
        tabBtns: document.querySelectorAll('.tab-btn'),
        tabPanes: document.querySelectorAll('.tab-pane'),
        tabMini: document.getElementById('tab-mini'),
        tabDetailed: document.getElementById('tab-detailed'),
        tabHost: document.getElementById('tab-host'),
        
        // Previews
        iframeMini: document.getElementById('iframe-mini'),
        iframeDetailed: document.getElementById('iframe-detailed'),
        iframeHost: document.getElementById('iframe-host'),
        btnActionDlTabs: document.querySelectorAll('.btn-action-dl-tab'),
        
        toastContainer: document.getElementById('toast-container')
    };

    // -------------------------------------------------------------------------
    // 1. INITIALIZATION & BINDINGS
    // -------------------------------------------------------------------------
    function init() {
        setupEventListeners();
        renderIgnoredTags();
    }

    function setupEventListeners() {
        // Drag and drop events
        elements.dropZone.addEventListener('click', () => elements.fileInput.click());
        elements.fileInput.addEventListener('change', handleFileSelect);
        elements.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            elements.dropZone.classList.add('drag-active');
        });
        elements.dropZone.addEventListener('dragleave', () => {
            elements.dropZone.classList.remove('drag-active');
        });
        elements.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            elements.dropZone.classList.remove('drag-active');
            if (e.dataTransfer.files.length > 0) {
                processFiles(e.dataTransfer.files);
            }
        });

        // Checkboxes settings change
        [elements.chkIp, elements.chkMac, elements.chkNetbios, elements.chkNa].forEach(chk => {
            chk.addEventListener('change', () => {
                state.showIP = elements.chkIp.checked;
                state.showMAC = elements.chkMac.checked;
                state.showNetBios = elements.chkNetbios.checked;
                state.showNA = elements.chkNa.checked;
                analyzeData();
            });
        });

        // CVSS Threshold slider
        elements.cvssThreshold.addEventListener('input', (e) => {
            const val = parseFloat(e.target.value).toFixed(1);
            elements.cvssVal.textContent = val;
            state.minCvss = parseFloat(val);
            analyzeData();
        });

        // Ignored List Add/Reset
        elements.btnAddIgnored.addEventListener('click', addIgnoredItem);
        elements.ignoredInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') addIgnoredItem();
        });
        elements.btnResetIgnored.addEventListener('click', () => {
            state.ignoredVulns = [...DEFAULT_IGNORED_VULNERABILITIES];
            renderIgnoredTags();
            analyzeData();
            showToast("Ignored list reset to defaults.", "success");
        });

        // Tab Switching
        elements.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.classList.contains('disabled')) return;
                
                elements.tabBtns.forEach(b => b.classList.remove('active'));
                elements.tabPanes.forEach(p => p.classList.remove('active'));
                
                btn.classList.add('active');
                const paneId = btn.getAttribute('data-tab');
                document.getElementById(paneId).classList.add('active');
            });
        });

        // Exporter downloads
        elements.btnDlMini.addEventListener('click', () => downloadReport('mini'));
        elements.btnDlDetailed.addEventListener('click', () => downloadReport('detailed'));
        elements.btnDlHost.addEventListener('click', () => downloadReport('host'));
        elements.btnMergeScans.addEventListener('click', mergeAndDownloadScans);
        elements.btnActionDlTabs.forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.getAttribute('data-target');
                downloadReport(target);
            });
        });

        // Search & Severity Filters in Table Explorer
        elements.explorerSearch.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            renderExplorerTable();
        });

        elements.filterPills.forEach(pill => {
            pill.addEventListener('click', () => {
                elements.filterPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                state.severityFilter = pill.getAttribute('data-filter');
                renderExplorerTable();
            });
        });
    }

    // -------------------------------------------------------------------------
    // 2. FILE LOADING AND MANAGEMENT
    // -------------------------------------------------------------------------
    function handleFileSelect(e) {
        if (e.target.files.length > 0) {
            processFiles(e.target.files);
        }
    }

    function processFiles(fileList) {
        let loadedCount = 0;
        Array.from(fileList).forEach(file => {
            if (!file.name.endsWith('.nessus')) {
                showToast(`Skipped "${file.name}": Only .nessus files allowed.`, "error");
                return;
            }

            // Check if file is already loaded
            if (state.files.some(f => f.name === file.name && f.size === file.size)) {
                showToast(`"${file.name}" is already loaded.`, "error");
                return;
            }

            const reader = new FileReader();
            reader.onload = function (e) {
                state.files.push({
                    name: file.name,
                    size: formatBytes(file.size),
                    rawText: e.target.result
                });
                loadedCount++;

                if (loadedCount === Array.from(fileList).filter(f => f.name.endsWith('.nessus')).length) {
                    onFilesUpdated();
                }
            };
            reader.readAsText(file);
        });
    }

    function onFilesUpdated() {
        if (state.files.length > 0) {
            elements.loadedFilesContainer.style.display = 'block';
            elements.fileCount.textContent = state.files.length;
            renderFileList();
            analyzeData();
            showToast(`${state.files.length} scans active. Parsing completed!`, "success");
        } else {
            elements.loadedFilesContainer.style.display = 'none';
            resetDashboard();
        }
    }

    function renderFileList() {
        elements.fileList.innerHTML = '';
        state.files.forEach((file, index) => {
            const li = document.createElement('li');
            li.className = 'file-item';
            li.innerHTML = `
                <div class="file-name-meta">
                    <span class="file-name-txt" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
                    <span class="file-size-txt">${file.size}</span>
                </div>
                <button type="button" class="btn-remove-file" data-index="${index}" title="Remove file">×</button>
            `;
            elements.fileList.appendChild(li);
        });

        // Bind delete button events
        elements.fileList.querySelectorAll('.btn-remove-file').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(btn.getAttribute('data-index'));
                state.files.splice(idx, 1);
                onFilesUpdated();
            });
        });
    }

    function resetDashboard() {
        elements.emptyState.style.display = 'flex';
        elements.dashboardActive.style.display = 'none';
        
        // Disable Report buttons and preview tabs
        [elements.tabMini, elements.tabDetailed, elements.tabHost].forEach(t => t.classList.add('disabled'));
        
        // Reset preview iframes
        elements.iframeMini.srcdoc = '';
        elements.iframeDetailed.srcdoc = '';
        elements.iframeHost.srcdoc = '';
        
        // Activate Dashboard button
        elements.tabBtns.forEach(b => b.classList.remove('active'));
        elements.tabPanes.forEach(p => p.classList.remove('active'));
        elements.tabBtns[0].classList.add('active');
        elements.tabPanes[0].classList.add('active');
    }

    // -------------------------------------------------------------------------
    // 3. XML PARSING & VULNERABILITY MODEL GENERATION (JAXB Equivalent)
    // -------------------------------------------------------------------------
    function analyzeData() {
        if (state.files.length === 0) {
            resetDashboard();
            return;
        }

        const parser = new DOMParser();
        const mergedHosts = new Map(); // hostIdentifier -> { name, mac, netbios, items: Map(pluginName -> item) }

        state.files.forEach(fileObj => {
            try {
                const xmlDoc = parser.parseFromString(fileObj.rawText, "text/xml");
                
                // Get report hosts
                const reportHosts = xmlDoc.getElementsByTagName("ReportHost");
                
                Array.from(reportHosts).forEach(hostEl => {
                    const hostName = hostEl.getAttribute("name") || "@@@NA";
                    
                    // Retrieve host property tags
                    let macAddress = "@@@NA";
                    let netbiosName = "@@@NA";
                    
                    const tags = hostEl.getElementsByTagName("tag");
                    Array.from(tags).forEach(tagEl => {
                        const nameAttr = tagEl.getAttribute("name");
                        const val = tagEl.textContent;
                        if (nameAttr === "mac-address") macAddress = val;
                        if (nameAttr === "netbios-name") netbiosName = val;
                    });

                    // Build dynamic host identifier matching getID() in Vulnerability.java
                    let hostIdentifier = "";
                    if (state.showIP) hostIdentifier += hostName;
                    
                    if (state.showMAC && (macAddress !== "@@@NA" || state.showNA)) {
                        hostIdentifier += ` (${macAddress})`;
                    }
                    if (state.showNetBios && (netbiosName !== "@@@NA" || state.showNA)) {
                        hostIdentifier += ` (${netbiosName})`;
                    }

                    // Ensure host map insertion
                    if (!mergedHosts.has(hostIdentifier)) {
                        mergedHosts.set(hostIdentifier, {
                            identifier: hostIdentifier,
                            rawName: hostName,
                            mac: macAddress,
                            netbios: netbiosName,
                            vulnsMap: new Map() // pluginName -> parsed ReportItem details
                        });
                    }
                    const hostRecord = mergedHosts.get(hostIdentifier);

                    // Get vulnerability findings
                    const reportItems = hostEl.getElementsByTagName("ReportItem");
                    Array.from(reportItems).forEach(itemEl => {
                        const pluginName = itemEl.getAttribute("pluginName") || "@@@NA";
                        const plugin_name = itemEl.getElementsByTagName("plugin_name")[0]?.textContent || "@@@NA";
                        const riskFactor = itemEl.getElementsByTagName("risk_factor")[0]?.textContent || "@@@NA";
                        const cvssBaseScore = itemEl.getElementsByTagName("cvss_base_score")[0]?.textContent || "@@@NA";
                        const cvssTemporalScore = itemEl.getElementsByTagName("cvss_temporal_score")[0]?.textContent || "@@@NA";
                        
                        const port = itemEl.getAttribute("port") || "@@@NA";
                        const svcName = itemEl.getAttribute("svc_name") || "@@@NA";
                        const protocol = itemEl.getAttribute("protocol") || "@@@NA";
                        const pluginID = itemEl.getAttribute("pluginID") || "@@@NA";
                        
                        const description = itemEl.getElementsByTagName("description")[0]?.textContent || "@@@NA";
                        const solution = itemEl.getElementsByTagName("solution")[0]?.textContent || "@@@NA";
                        const synopsis = itemEl.getElementsByTagName("synopsis")[0]?.textContent || "@@@NA";
                        const pluginOutput = itemEl.getElementsByTagName("plugin_output")[0]?.textContent || "@@@NA";

                        // Filter by Excluded Vulnerabilities List
                        if (state.ignoredVulns.includes(plugin_name) || state.ignoredVulns.includes(pluginName)) {
                            return;
                        }

                        // Parse CVSS Base Score
                        let cvssFloat = 0.0;
                        if (cvssBaseScore !== "@@@NA") {
                            cvssFloat = parseFloat(cvssBaseScore);
                        }

                        // Filter by Minimum CVSS Base Score threshold
                        if (cvssFloat < state.minCvss) {
                            return;
                        }

                        // Ignore if cvssBaseScore is missing or <= 0 (matching Java filter of Float.parseFloat(ri.cvssBaseScore) > 0)
                        // If threshold is 0.0, we can also include information items (None / cvss 0) to be user friendly
                        if (state.minCvss > 0.0 && cvssFloat <= 0) {
                            return;
                        }

                        const parsedItem = {
                            pluginID,
                            pluginName,
                            plugin_name,
                            port,
                            svcName,
                            protocol,
                            riskFactor: mapRiskFactor(riskFactor, cvssFloat),
                            cvssBaseScore: cvssBaseScore,
                            cvssFloat: cvssFloat,
                            cvssTempScore: cvssTemporalScore,
                            description,
                            solution,
                            synopsis,
                            pluginOutput
                        };

                        // Store unique vulnerability item per host
                        hostRecord.vulnsMap.set(pluginName, parsedItem);
                    });
                });
            } catch (err) {
                console.error("Error parsing Nessus XML:", err);
                showToast(`Failed parsing XML in ${fileObj.name}`, "error");
            }
        });

        // ---------------------------------------------------------------------
        // 4. MERGING & SANITIZING VULNERABILITIES (Matching Vulnerability.java)
        // ---------------------------------------------------------------------
        // Group and consolidate findings globally by unique vulnerability (pluginName)
        const globalVulnsMap = new Map(); // pluginName -> globalVulnerability
        
        mergedHosts.forEach(hostRecord => {
            hostRecord.vulnsMap.forEach((item, pluginName) => {
                if (!globalVulnsMap.has(pluginName)) {
                    globalVulnsMap.set(pluginName, {
                        pluginName: item.pluginName,
                        riskFactor: item.riskFactor,
                        cvssBaseScore: item.cvssBaseScore,
                        cvssFloat: item.cvssFloat,
                        cvssTempScore: item.cvssTempScore,
                        port: item.port,
                        synopsis: item.synopsis,
                        description: item.description,
                        solution: item.solution,
                        affectedHosts: [] // list of hostIdentifiers
                    });
                }
                const globalRecord = globalVulnsMap.get(pluginName);
                if (!globalRecord.affectedHosts.includes(hostRecord.identifier)) {
                    globalRecord.affectedHosts.push(hostRecord.identifier);
                }
            });
        });

        let vulnerabilities = Array.from(globalVulnsMap.values());

        // Perform group-merging of similar vulnerabilities (PHP, Apache, OpenSSL)
        vulnerabilities = mergeSameRiskFactorVulnerability(vulnerabilities);

        // Sanitize vulnerabilities (MSXX-0XX Microsoft security bulletin links, stripping uncredentialed check, etc.)
        vulnerabilities.forEach(v => sanitizeVulnerability(v));

        // Sort globally by CVSS Base Score (descending)
        vulnerabilities.sort((a, b) => b.cvssFloat - a.cvssFloat);

        // Map vulnerabilities back to individual host models
        const finalHosts = [];
        mergedHosts.forEach(hostRecord => {
            const hostVulns = [];
            vulnerabilities.forEach(v => {
                if (v.affectedHosts.includes(hostRecord.identifier)) {
                    hostVulns.push(v);
                }
            });
            if (hostVulns.length > 0) {
                finalHosts.push({
                    identifier: hostRecord.identifier,
                    rawName: hostRecord.rawName,
                    mac: hostRecord.mac,
                    netbios: hostRecord.netbios,
                    vulnerabilitiesInHost: hostVulns
                });
            }
        });
        finalHosts.sort((a, b) => a.identifier.localeCompare(b.identifier));

        // Update State
        state.vulnerabilities = vulnerabilities;
        state.hosts = finalHosts;

        // Render Dashboard UI elements
        updateDashboardUI();
    }

    // Map risk_factor strings or CVSS ranges into standard ratings
    function mapRiskFactor(risk, cvss) {
        if (risk && risk !== "@@@NA" && risk !== "None") return risk;
        if (cvss >= 9.0) return "Critical";
        if (cvss >= 7.0) return "High";
        if (cvss >= 4.0) return "Medium";
        if (cvss >= 0.1) return "Low";
        return "Info";
    }

    // Consolidate identical vulnerability kinds per severity (PHP, Apache, OpenSSL with '<')
    function mergeSameRiskFactorVulnerability(vulnList) {
        const critical = vulnList.filter(v => v.riskFactor === "Critical");
        const high = vulnList.filter(v => v.riskFactor === "High");
        const medium = vulnList.filter(v => v.riskFactor === "Medium");
        const low = vulnList.filter(v => v.riskFactor === "Low");
        const info = vulnList.filter(v => v.riskFactor === "Info");

        const mergedList = [];
        if (critical.length > 0) mergedList.push(...mergeSameRiskFactorGroup(critical));
        if (high.length > 0) mergedList.push(...mergeSameRiskFactorGroup(high));
        if (medium.length > 0) mergedList.push(...mergeSameRiskFactorGroup(medium));
        if (low.length > 0) mergedList.push(...mergeSameRiskFactorGroup(low));
        if (info.length > 0) mergedList.push(...mergeSameRiskFactorGroup(info));

        return mergedList;
    }

    function mergeSameRiskFactorGroup(list) {
        const phpVulns = [];
        const apacheVulns = [];
        const openSSLVulns = [];
        const standardVulns = [];

        list.forEach(v => {
            const name = v.pluginName;
            if (name.includes("PHP ") && name.includes("<")) {
                phpVulns.push(v);
            } else if (name.includes("Apache ") && name.includes("<")) {
                apacheVulns.push(v);
            } else if (name.includes("OpenSSL ") && name.includes("<")) {
                openSSLVulns.push(v);
            } else {
                standardVulns.push(v);
            }
        });

        const result = [...standardVulns];
        if (phpVulns.length > 0) result.push(mergeSameKindGroup(phpVulns));
        if (apacheVulns.length > 0) result.push(mergeSameKindGroup(apacheVulns));
        if (openSSLVulns.length > 0) result.push(mergeSameKindGroup(openSSLVulns));
        return result;
    }

    function mergeSameKindGroup(list) {
        // Sort sub-group descending by CVSS
        list.sort((a, b) => b.cvssFloat - a.cvssFloat);
        
        // Deep copy highest severity element as base
        const base = Object.assign({}, list[0]);
        base.affectedHosts = [...base.affectedHosts];

        // Gather and merge unique affected systems from other elements in group
        list.forEach(item => {
            item.affectedHosts.forEach(host => {
                if (!base.affectedHosts.includes(host)) {
                    base.affectedHosts.push(host);
                }
            });
        });
        base.affectedHosts.sort();
        return base;
    }

    // Text sanitization logic matching sanitizeMSXX0XXVulns in Vulnerability.java
    function sanitizeVulnerability(v) {
        // Remove (uncredentialed check) and (remote check)
        let name = v.pluginName
            .replace(/\(uncredentialed check\)/gi, "")
            .replace(/\(remote check\)/gi, "")
            .trim();

        // Remove empty parentheses () or parentheses wrapping pure floating numbers (e.g. (1.5))
        name = name.replace(/\(\s*\)/g, "");
        const numParenRegex = /\(([^)]+)\)/g;
        let match;
        while ((match = numParenRegex.exec(name)) !== null) {
            const inner = match[1];
            if (!isNaN(parseFloat(inner)) && isFinite(inner)) {
                name = name.replace(`(${inner})`, "").replace(/\(\s*\)/g, "").trim();
            }
        }
        v.pluginName = name.replace(/\s+/g, " ");

        // MSXX-0XX Solution redirection formatting link replacement
        const msRegex = /MS([0-9]{2}-[0-9]{3}):/i;
        const msMatch = msRegex.exec(name);
        if (msMatch) {
            const tag = msMatch[0].replace(":", "");
            v.solution = `<p align="left">Install the patch as per <br/>https://technet.microsoft.com/en-us/library/security/${tag}</p>`;
        }
    }

    // -------------------------------------------------------------------------
    // 5. MERGER ENGINE (Consolidates raw XML documents)
    // -------------------------------------------------------------------------
    function mergeAndDownloadScans() {
        if (state.files.length === 0) return;

        showToast("Merging selected Nessus scans...", "info");
        const parser = new DOMParser();
        
        // Initialize merged DOM document with first file
        const mergedDoc = parser.parseFromString(state.files[0].rawText, "text/xml");
        const mergedReport = mergedDoc.getElementsByTagName("Report")[0];
        
        if (!mergedReport) {
            showToast("Invalid Nessus format in base file.", "error");
            return;
        }

        // Wipe base report hosts list to build fresh merged node structure
        const existingHostsNode = mergedReport.getElementsByTagName("ReportHost");
        Array.from(existingHostsNode).forEach(node => mergedReport.removeChild(node));

        // Maps to track and resolve hosts and their report items
        const hostElementsMap = new Map(); // hostName -> host XML Element

        state.files.forEach(fileObj => {
            const doc = parser.parseFromString(fileObj.rawText, "text/xml");
            const fileHosts = doc.getElementsByTagName("ReportHost");

            Array.from(fileHosts).forEach(bRH => {
                const hostName = bRH.getAttribute("name");
                
                // If Host is not in Merged Report yet, deep clone and insert
                if (!hostElementsMap.has(hostName)) {
                    const clonedHost = mergedDoc.importNode(bRH, true);
                    mergedReport.appendChild(clonedHost);
                    hostElementsMap.set(hostName, clonedHost);
                } else {
                    // Host already exists in merged document, merge individual ReportItems
                    const aRH = hostElementsMap.get(hostName);
                    const bItems = bRH.getElementsByTagName("ReportItem");

                    Array.from(bItems).forEach(bItem => {
                        const pluginName = bItem.getAttribute("pluginName");
                        
                        // Check if this ReportItem exists in the merged Host
                        const aItems = aRH.getElementsByTagName("ReportItem");
                        let isItemFound = false;
                        for (let i = 0; i < aItems.length; i++) {
                            if (aItems[i].getAttribute("pluginName") === pluginName) {
                                isItemFound = true;
                                break;
                            }
                        }

                        // If not present, import and append it
                        if (!isItemFound) {
                            const clonedItem = mergedDoc.importNode(bItem, true);
                            aRH.appendChild(clonedItem);
                        }
                    });
                }
            });
        });

        // Serialize and trigger download
        const serializer = new XMLSerializer();
        const xmlString = serializer.serializeToString(mergedDoc);

        const blob = new Blob([xmlString], { type: "text/xml;charset=utf-8" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "Merged_Nessus_Scan.nessus";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Unified Nessus file merged and downloaded successfully!", "success");
    }

    // -------------------------------------------------------------------------
    // 6. DASHBOARD & INTERACTIVE EXPLORER RENDERING
    // -------------------------------------------------------------------------
    function updateDashboardUI() {
        elements.emptyState.style.display = 'none';
        elements.dashboardActive.style.display = 'block';

        // Unlock report buttons & preview tabs
        [elements.tabMini, elements.tabDetailed, elements.tabHost].forEach(t => t.classList.remove('disabled'));

        // Header and quick stats count
        elements.statHosts.textContent = state.hosts.length;
        elements.statVulns.textContent = state.vulnerabilities.length;
        elements.statScans.textContent = state.files.length;

        // Compute severity metrics counts
        const critical = state.vulnerabilities.filter(v => v.riskFactor === "Critical").length;
        const high = state.vulnerabilities.filter(v => v.riskFactor === "High").length;
        const medium = state.vulnerabilities.filter(v => v.riskFactor === "Medium").length;
        const low = state.vulnerabilities.filter(v => v.riskFactor === "Low").length;

        elements.countCritical.textContent = critical;
        elements.countHigh.textContent = high;
        elements.countMedium.textContent = medium;
        elements.countLow.textContent = low;

        // Render CSS animated severity distribution bar segments
        const total = critical + high + medium + low || 1;
        elements.barCritical.style.width = `${(critical / total) * 100}%`;
        elements.barHigh.style.width = `${(high / total) * 100}%`;
        elements.barMedium.style.width = `${(medium / total) * 100}%`;
        elements.barLow.style.width = `${(low / total) * 100}%`;

        // Render Explorer Table
        renderExplorerTable();

        // Render Live Iframe report previews
        refreshReportPreviews();
    }

    function renderExplorerTable() {
        elements.explorerTableBody.innerHTML = '';

        // Apply filters
        const filtered = state.vulnerabilities.filter(v => {
            const matchesSearch = v.pluginName.toLowerCase().includes(state.searchQuery) ||
                v.affectedHosts.some(h => h.toLowerCase().includes(state.searchQuery));
            
            const matchesSeverity = state.severityFilter === "all" || v.riskFactor === state.severityFilter;

            return matchesSearch && matchesSeverity;
        });

        if (filtered.length === 0) {
            elements.explorerTableBody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 36px;">
                        No matching vulnerabilities found. Try broadening your query filters.
                    </td>
                </tr>
            `;
            return;
        }

        filtered.forEach(v => {
            const tr = document.createElement('tr');
            
            // Build affected hosts badges HTML
            const hostBadges = v.affectedHosts.map(h => `<span class="host-badge-item">${escapeHtml(h)}</span>`).join('');

            tr.innerHTML = `
                <td>
                    <div class="explorer-vname" title="${escapeHtml(v.pluginName)}">${escapeHtml(v.pluginName)}</div>
                </td>
                <td class="center-align">
                    <span class="severity-pill-badge" style="background-color: rgba(${getSeverityRgb(v.riskFactor)}, 0.1); color: rgb(${getSeverityRgb(v.riskFactor)}); border: 1px solid rgba(${getSeverityRgb(v.riskFactor)}, 0.2)">
                        ${v.riskFactor}
                    </span>
                </td>
                <td class="center-align">
                    <span class="cvss-score-label" style="color: rgb(${getSeverityRgb(v.riskFactor)})">${v.cvssBaseScore}</span>
                </td>
                <td>
                    <div class="affected-hosts-badges">${hostBadges}</div>
                </td>
            `;
            elements.explorerTableBody.appendChild(tr);
        });
    }

    // Helper functions for UI styling values
    function getSeverityRgb(severity) {
        if (severity === "Critical") return "225, 29, 72"; // var(--color-critical)
        if (severity === "High") return "244, 63, 94";     // var(--color-high)
        if (severity === "Medium") return "249, 115, 22";  // var(--color-medium)
        if (severity === "Low") return "16, 185, 129";    // var(--color-low)
        return "6, 182, 212";                             // var(--color-info)
    }

    function getSeverityHexColor(severity) {
        if (severity === "Critical") return "#C00000";
        if (severity === "High") return "#FF0000";
        if (severity === "Medium") return "#ED7D31";
        if (severity === "Low") return "#00B050";
        return "#00B0F0";
    }

    function getSeverityStars(severity) {
        if (severity === "Critical") return "★ ★ ★ ★ ★";
        if (severity === "High") return "★ ★ ★ ★";
        if (severity === "Medium") return "★ ★ ★";
        if (severity === "Low") return "★ ★";
        return "★";
    }

    // -------------------------------------------------------------------------
    // 7. EXPORT TEMPLATE GENERATOR & EXPORTER
    // -------------------------------------------------------------------------
    function refreshReportPreviews() {
        const miniHTML = compileMiniReportHTML();
        const detailedHTML = compileDetailedReportHTML();
        const hostHTML = compileReportByHostHTML();

        elements.iframeMini.srcdoc = miniHTML;
        elements.iframeDetailed.srcdoc = detailedHTML;
        elements.iframeHost.srcdoc = hostHTML;
    }

    function downloadReport(reportType) {
        if (state.files.length === 0) return;

        let content = "";
        let filename = "";

        if (reportType === 'mini') {
            content = compileMiniReportHTML();
            filename = "Nessus_Mini_Report.html";
        } else if (reportType === 'detailed') {
            content = compileDetailedReportHTML();
            filename = "Nessus_Detailed_Report.html";
        } else if (reportType === 'host') {
            content = compileReportByHostHTML();
            filename = "Nessus_Report_By_Host.html";
        }

        const blob = new Blob([content], { type: "text/html;charset=utf-8" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast(`Report downloaded successfully!`, "success");
    }

    // Modern styled template compilers for exported reports
    // Fully matching original format parameters, but utilizing modern responsive CSS design layouts!
    function compileMiniReportHTML() {
        const rows = state.vulnerabilities.map(v => `
            <tr>
                <td class="vulName">${escapeHtml(v.pluginName)}</td>
                <td class="colorfuls" style="color: ${getSeverityHexColor(v.riskFactor)};">${getSeverityStars(v.riskFactor)}</td>
                <td class="colorfuls" style="color: ${getSeverityHexColor(v.riskFactor)};">${v.riskFactor}</td>
                <td class="remarks">${v.solution}</td>
            </tr>
            <tr>
                <td class="remarks" colspan="4"><strong>Affected Systems:</strong> ${escapeHtml(v.affectedHosts.join(", "))}</td>
            </tr>
        `).join('');

        return `<!DOCTYPE html>
<html>
<head>
    <title>Mini Report: ${escapeHtml(state.reportName)}</title>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #fafbfc; color: #333; padding: 30px; margin: 0; }
        h1 { font-family: 'Outfit', sans-serif; color: #1e293b; font-size: 24px; margin-bottom: 24px; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
        .detable { width: 100%; border-collapse: collapse; border-spacing: 0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); border-radius: 8px; overflow: hidden; background-color: #fff; border: 1px solid #e2e8f0; }
        .detable th { font-weight: 600; padding: 12px 18px; border-bottom: 2px solid #cbd5e1; text-align: left; background-color: #f1f5f9; color: #475569; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
        .detable td { padding: 12px 18px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #334155; line-height: 1.5; }
        .detable tr:nth-child(4n-3), .detable tr:nth-child(4n-2) { background-color: #fff; }
        .detable tr:nth-child(4n-1), .detable tr:nth-child(4n) { background-color: #f8fafc; }
        .detable .tableHeader { font-weight: bold; background-color: #e2e8f0; text-align: center; }
        .detable .colorfuls { font-weight: bold; text-align: center; vertical-align: middle; white-space: nowrap; }
        .detable .remarks { vertical-align: top; text-align: left; }
        .detable .vulName { text-align: left; vertical-align: top; font-weight: bold; color: #0f172a; }
    </style>
</head>
<body>
    <h1>Mini Security Report: ${escapeHtml(state.reportName)}</h1>
    <table class="detable">
        <thead>
            <tr>
                <th width="40%">Vulnerability</th>
                <th width="15%" style="text-align:center;">Criticality</th>
                <th width="15%" style="text-align:center;">Impact on Business</th>
                <th width="30%">Remarks / Solution</th>
            </tr>
        </thead>
        <tbody>
            ${rows}
        </tbody>
    </table>
</body>
</html>`;
    }

    function compileDetailedReportHTML() {
        const blocks = state.vulnerabilities.map(v => `
            <div class="vuln-block" style="border-left: 5px solid ${getSeverityHexColor(v.riskFactor)};">
                <p class="vuln-header-txt">Vulnerability Name: ${escapeHtml(v.pluginName)}</p>
                <p class="meta-line"><strong>Risk Level:</strong> <span style="color:${getSeverityHexColor(v.riskFactor)};">${getSeverityStars(v.riskFactor)}</span></p>
                <p class="meta-line"><strong>Impact on Business:</strong> <span style="font-weight: 600; color: ${getSeverityHexColor(v.riskFactor)};">${v.riskFactor}</span></p>
                <p class="meta-line"><strong>Synopsis:</strong> ${escapeHtml(v.synopsis)}</p>
                <p class="meta-line"><strong>Solution Description:</strong> Apply patches/remediations details described below.</p>
                
                <table class="tg">
                    <thead>
                        <tr>
                            <th class="ipTitle">Affected IP Addresses / Host Names</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="ipAddress">${escapeHtml(v.affectedHosts.join(", "))}</td>
                        </tr>
                        <tr>
                            <td style="padding: 20px;">
                                <div class="inner-title-bar" style="background-color:${getSeverityHexColor(v.riskFactor)};">
                                    ${escapeHtml(v.pluginName)}
                                </div>
                                <div class="blockTitle">Synopsis</div>
                                <div class="blockDescription">${escapeHtml(v.synopsis)}</div>
                                
                                <div class="blockTitle">Description</div>
                                <div class="blockDescription">${escapeHtml(v.description)}</div>
                                
                                <div class="blockTitle">Remediation / Solution</div>
                                <div class="blockDescription">${v.solution}</div>
                                
                                <div class="blockTitle">CVSS Base Score Rating</div>
                                <div class="blockDescription">
                                    <strong style="color: ${getSeverityHexColor(v.riskFactor)}; font-size: 15px;">${v.cvssBaseScore}</strong> (${v.riskFactor})
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        `).join('');

        return `<!DOCTYPE html>
<html>
<head>
    <title>Detailed Report: ${escapeHtml(state.reportName)}</title>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #fafbfc; color: #333; padding: 30px; margin: 0; line-height: 1.6; }
        h1 { font-family: 'Outfit', sans-serif; color: #1e293b; font-size: 24px; margin-bottom: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
        .vuln-block { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; margin-bottom: 40px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.04); }
        .vuln-header-txt { font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 16px 0; }
        .meta-line { font-size: 13px; color: #475569; margin: 4px 0 10px 0; }
        .tg { width: 100%; border-collapse: collapse; border-spacing: 0; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden; margin-top: 20px; }
        .tg td, .tg th { border: 1px solid #cbd5e1; font-size: 13px; color: #334155; }
        .tg .ipTitle { font-weight: 700; background-color: #f1f5f9; color: #475569; vertical-align: top; padding: 10px; text-align: center; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #cbd5e1; }
        .tg .ipAddress { vertical-align: top; text-align: center; padding: 12px; font-family: monospace; font-size: 14px; background-color: #f8fafc; color: #0f172a; font-weight: 600; }
        .inner-title-bar { font-weight: bold; padding: 12px; color: white; font-size: 15px; border-radius: 4px; margin-bottom: 20px; }
        .blockTitle { padding: 6px 12px; font-weight: 700; background-color: #f1f5f9; color: #334155; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-radius: 4px; display: inline-block; margin-bottom: 8px; }
        .blockDescription { padding: 4px 12px 20px 12px; text-align: justify; color: #334155; font-size: 13px; line-height: 1.6; }
    </style>
</head>
<body>
    <h1>Detailed Vulnerability Report: ${escapeHtml(state.reportName)}</h1>
    ${blocks}
</body>
</html>`;
    }

    function compileReportByHostHTML() {
        const tables = state.hosts.map(host => {
            const rows = host.vulnerabilitiesInHost.map(v => `
                <tr>
                    <td class="table-Vulnerability">${escapeHtml(v.pluginName)}</td>
                    <td class="table-Criticality" style="color: ${getSeverityHexColor(v.riskFactor)};">${v.riskFactor}</td>
                    <td class="table-Solution">${v.solution}</td>
                </tr>
            `).join('');

            return `
            <table class="table">
                <thead>
                    <tr>
                        <th class="table-IPAddress" colspan="3">Asset: ${escapeHtml(host.identifier)}</th>
                    </tr>
                    <tr>
                        <th width="35%" class="table-Heading">Vulnerability</th>
                        <th width="15%" class="table-Heading" style="text-align:center;">Criticality</th>
                        <th width="50%" class="table-Heading">Solution</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
            <div class="table-spacing"></div>
            `;
        }).join('');

        return `<!DOCTYPE html>
<html>
<head>
    <title>Report By Host: ${escapeHtml(state.reportName)}</title>
    <style type="text/css">
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #fafbfc; color: #333; padding: 30px; margin: 0; }
        h1 { font-family: 'Outfit', sans-serif; color: #1e293b; font-size: 24px; margin-bottom: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
        .table { width: 100%; border-collapse: collapse; border-spacing: 0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.04); border-radius: 8px; overflow: hidden; background-color: #fff; border: 1px solid #cbd5e1; margin-bottom: 16px; }
        .table td { padding: 12px 18px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #334155; line-height: 1.5; }
        .table th { font-weight: 600; padding: 12px 18px; text-align: left; }
        .table .table-IPAddress { font-weight: 700; font-size: 15px; background-color: #1e3a8a; color: #ffffff; text-align: left; padding: 14px 20px; border-bottom: 2px solid #cbd5e1; }
        .table .table-Vulnerability { font-weight: 700; color: #0f172a; vertical-align: middle; }
        .table .table-Heading { font-weight: 600; font-size: 12px; background-color: #f1f5f9; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #cbd5e1; }
        .table .table-Criticality { font-weight: 700; text-align: center; vertical-align: middle; white-space: nowrap; }
        .table .table-Solution { vertical-align: middle; }
        .table-spacing { height: 36px; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report By Host: ${escapeHtml(state.reportName)}</h1>
    ${tables}
</body>
</html>`;
    }

    // -------------------------------------------------------------------------
    // 8. SETTINGS IGNORED LIST MANAGER
    // -------------------------------------------------------------------------
    function addIgnoredItem() {
        const val = elements.ignoredInput.value.trim();
        if (val) {
            if (state.ignoredVulns.includes(val)) {
                showToast("This item is already excluded.", "error");
                return;
            }
            state.ignoredVulns.push(val);
            elements.ignoredInput.value = "";
            renderIgnoredTags();
            analyzeData();
            showToast(`Added "${val}" to exclude list.`, "success");
        }
    }

    function renderIgnoredTags() {
        elements.ignoredTagsWrapper.innerHTML = "";
        state.ignoredVulns.forEach((title, index) => {
            const tag = document.createElement("span");
            tag.className = "ignored-tag";
            tag.innerHTML = `
                ${escapeHtml(title)}
                <span data-index="${index}">×</span>
            `;
            elements.ignoredTagsWrapper.appendChild(tag);
        });

        // Bind remove element triggers
        elements.ignoredTagsWrapper.querySelectorAll('span[data-index]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(btn.getAttribute('data-index'));
                const removedTitle = state.ignoredVulns.splice(idx, 1)[0];
                renderIgnoredTags();
                analyzeData();
                showToast(`Removed "${removedTitle}" from exclude list.`, "success");
            });
        });
    }

    // -------------------------------------------------------------------------
    // 9. HELPER UTILITIES
    // -------------------------------------------------------------------------
    function showToast(message, type = "info") {
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        
        const icon = type === "success" ? "✅" : type === "error" ? "❌" : "ℹ️";
        toast.innerHTML = `
            <span>${icon}</span>
            <span>${message}</span>
        `;
        
        elements.toastContainer.appendChild(toast);
        
        // Auto-remove toast after 4s
        setTimeout(() => {
            toast.style.animation = "slideIn 0.3s reverse forwards";
            setTimeout(() => {
                elements.toastContainer.removeChild(toast);
            }, 300);
        }, 4000);
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // Initialize application execution
    document.addEventListener('DOMContentLoaded', init);

})();
