#!/usr/bin/env node
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const PORT = process.env.MAX_DASHBOARD_PORT || 8181;
const LOG_DIR = '/tmp/moltbot';
const AUTH_DISABLED = process.env.MAX_DASHBOARD_NO_AUTH === 'true';

// Moltbot config paths (check both .moltbot and .clawdbot)
const MOLTBOT_CONFIG_PATHS = [
    path.join(os.homedir(), '.moltbot/moltbot.json'),
    path.join(os.homedir(), '.clawdbot/clawdbot.json')
];

// Get gateway auth token from Molt.bot config
function getAuthToken() {
    for (const configPath of MOLTBOT_CONFIG_PATHS) {
        try {
            if (fs.existsSync(configPath)) {
                const data = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
                // Get gateway auth token
                if (data.gateway?.auth?.token) {
                    return data.gateway.auth.token;
                }
            }
        } catch (e) {
            // Continue to next path
        }
    }
    return null;
}

// Session management for 24-hour auth
const crypto = require('crypto');
const activeSessions = new Map();
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function getSessionFromCookie(req) {
    const cookies = req.headers.cookie;
    if (!cookies) return null;

    const match = cookies.match(/max_session=([^;]+)/);
    if (!match) return null;

    const sessionId = match[1];
    const session = activeSessions.get(sessionId);

    if (session && Date.now() < session.expires) {
        return sessionId;
    }

    // Session expired, remove it
    if (session) {
        activeSessions.delete(sessionId);
    }
    return null;
}

function createSession() {
    const sessionId = generateSessionId();
    activeSessions.set(sessionId, {
        created: Date.now(),
        expires: Date.now() + SESSION_DURATION
    });
    return sessionId;
}

// HTTP Basic Auth check with session support
function checkAuth(req, res) {
    if (AUTH_DISABLED) return true;

    const authToken = getAuthToken();
    if (!authToken) {
        console.warn('Warning: No auth token found in Molt.bot config. Authentication disabled.');
        return true;
    }

    // Check for existing valid session
    const existingSession = getSessionFromCookie(req);
    if (existingSession) {
        return true;
    }

    // Check Basic Auth
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return false;
    }

    try {
        const base64 = authHeader.slice(6);
        const decoded = Buffer.from(base64, 'base64').toString('utf-8');
        const [username, password] = decoded.split(':');

        // Username can be anything, password must match the auth token
        if (password === authToken) {
            // Create session and set cookie
            const sessionId = createSession();
            res.setHeader('Set-Cookie', `max_session=${sessionId}; Path=/; HttpOnly; Max-Age=${SESSION_DURATION / 1000}; SameSite=Strict`);
            return true;
        }
    } catch (e) {
        return false;
    }

    return false;
}

// Send 401 Unauthorized response
function sendUnauthorized(res) {
    res.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="MAX Dashboard"',
        'Content-Type': 'text/plain'
    });
    res.end('Unauthorized - Use your Molt.bot gateway auth token as password');
}

// System monitoring state
let lastCpuUsage = { idle: 0, total: 0 };

// Helper to get CPU usage
function getCpuUsage() {
    const cpus = os.cpus();
    let idle = 0, total = 0;
    
    cpus.forEach(cpu => {
        for (const type in cpu.times) {
            total += cpu.times[type];
        }
        idle += cpu.times.idle;
    });
    
    const idleDiff = idle - lastCpuUsage.idle;
    const totalDiff = total - lastCpuUsage.total;
    const usage = 100 - ~~(100 * idleDiff / totalDiff);
    
    lastCpuUsage = { idle, total };
    
    return isNaN(usage) ? 0 : usage;
}

// Helper to get memory usage
function getMemoryUsage() {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    const usagePercent = (used / total) * 100;

    return {
        total: (total / (1024 ** 3)).toFixed(2) + ' GB',
        used: (used / (1024 ** 3)).toFixed(2) + ' GB',
        free: (free / (1024 ** 3)).toFixed(2) + ' GB',
        percent: usagePercent.toFixed(1)
    };
}

// Cache for real-time CPU calculation
let lastCpuSample = null;

// Helper to get Molt.bot gateway process stats
function getGatewayProcessStats() {
    try {
        // Find moltbot gateway process by searching for node process running moltbot
        const psOutput = execSync('ps aux | grep -E "node.*moltbot|moltbot.*gateway" | grep -v grep | head -1', {
            encoding: 'utf-8',
            timeout: 5000
        }).trim();

        if (!psOutput) {
            return { running: false };
        }

        // Parse ps aux output: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
        const parts = psOutput.split(/\s+/);
        if (parts.length < 11) {
            return { running: false };
        }

        const pid = parseInt(parts[1]);
        const memPercent = parseFloat(parts[3]);
        const rssKb = parseInt(parts[5]); // RSS in KB
        const rssMb = (rssKb / 1024).toFixed(1);
        
        // Calculate real-time CPU usage from /proc/[pid]/stat
        let cpuPercent = 0;
        try {
            const statFile = `/proc/${pid}/stat`;
            if (fs.existsSync(statFile)) {
                const stat = fs.readFileSync(statFile, 'utf-8');
                const statParts = stat.split(' ');
                const utime = parseInt(statParts[13]); // User CPU time
                const stime = parseInt(statParts[14]); // System CPU time
                const totalTime = utime + stime;
                const now = Date.now();
                
                if (lastCpuSample && lastCpuSample.pid === pid) {
                    const timeDelta = (now - lastCpuSample.timestamp) / 1000; // seconds
                    const cpuDelta = totalTime - lastCpuSample.totalTime;
                    const clkTck = 100; // Clock ticks per second
                    cpuPercent = ((cpuDelta / clkTck) / timeDelta) * 100;
                    if (cpuPercent < 0) cpuPercent = 0;
                    if (cpuPercent > 100) cpuPercent = 100;
                }
                
                lastCpuSample = { pid, totalTime, timestamp: now };
            }
        } catch (e) {
            // Fall back to ps aux value
            cpuPercent = parseFloat(parts[2]);
        }

        // Get process uptime from /proc if available
        let uptime = null;
        try {
            const statFile = `/proc/${pid}/stat`;
            if (fs.existsSync(statFile)) {
                const stat = fs.readFileSync(statFile, 'utf-8');
                const statParts = stat.split(' ');
                const startTime = parseInt(statParts[21]); // Start time in clock ticks
                const clkTck = 100; // Usually 100 on Linux
                const uptimeSec = os.uptime() - (startTime / clkTck);

                if (uptimeSec > 0) {
                    const hours = Math.floor(uptimeSec / 3600);
                    const mins = Math.floor((uptimeSec % 3600) / 60);
                    uptime = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                }
            }
        } catch (e) {
            // Ignore uptime errors
        }

        // Count child processes (subagents, tools)
        let childCount = 0;
        try {
            const childOutput = execSync(`pgrep -P ${pid} | wc -l`, {
                encoding: 'utf-8',
                timeout: 2000
            }).trim();
            childCount = parseInt(childOutput) || 0;
        } catch (e) {
            // Ignore
        }

        return {
            running: true,
            pid,
            cpu: cpuPercent.toFixed(1),
            memory: memPercent.toFixed(1),
            rss: rssMb + ' MB',
            uptime: uptime || 'unknown',
            children: childCount
        };
    } catch (e) {
        return { running: false };
    }
}

// Helper to get today's log file
function getTodayLogFile() {
    const today = new Date().toISOString().split('T')[0];
    return path.join(LOG_DIR, `moltbot-${today}.log`);
}

// Helper to format time as relative
function formatTime(date) {
    if (!date) return '—';
    const now = Date.now();
    const diff = now - new Date(date).getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'just now';
}

// Get recent assistant messages from transcript
function getRecentAssistantMessages(sessionFile, limit = 5) {
    const messages = [];
    try {
        if (!fs.existsSync(sessionFile)) {
            // Try alternate paths
            let altPath = sessionFile.replace('.clawdbot', '.moltbot');
            if (!fs.existsSync(altPath)) {
                altPath = sessionFile.replace('.moltbot', '.clawdbot');
            }
            if (!fs.existsSync(altPath)) return messages;
            sessionFile = altPath;
        }

        const content = fs.readFileSync(sessionFile, 'utf-8');
        const lines = content.trim().split('\n').filter(l => l.trim());
        
        // Read from end, looking for assistant messages
        for (let i = lines.length - 1; i >= 0 && messages.length < limit; i--) {
            try {
                const entry = JSON.parse(lines[i]);
                // Moltbot format: {type: "message", message: {role: "assistant", content: [...]}}
                const msg = entry.message || entry;
                if (msg.role === 'assistant' && msg.content) {
                    // Extract text content from assistant message
                    let textContent = '';
                    if (Array.isArray(msg.content)) {
                        for (const block of msg.content) {
                            if (block.type === 'text' && block.text) {
                                textContent += block.text + ' ';
                            }
                        }
                    } else if (typeof msg.content === 'string') {
                        textContent = msg.content;
                    }
                    
                    const trimmed = textContent.trim();
                    if (trimmed && trimmed !== 'HEARTBEAT_OK' && trimmed !== 'NO_REPLY' && !trimmed.startsWith('HEARTBEAT')) {
                        messages.unshift({
                            text: textContent.trim().substring(0, 300),
                            timestamp: entry.timestamp || msg.timestamp || Date.now()
                        });
                    }
                }
            } catch (e) {
                // Skip malformed lines
            }
        }
    } catch (error) {
        // Silently fail
    }
    return messages;
}

// Tool name descriptions
const TOOL_DESCRIPTIONS = {
    'process': 'Shell Command',
    'read': 'Read File',
    'write': 'Write File',
    'edit': 'Edit File',
    'search': 'Search Files',
    'grep': 'Search Content',
    'glob': 'Find Files',
    'web_search': 'Web Search',
    'web_fetch': 'Fetch URL',
    'browser': 'Browser Action',
    'memory': 'Memory Store',
    'recall': 'Memory Recall',
    'task': 'Background Task',
    'mcp': 'MCP Tool',
    'image': 'Image Processing',
    'code': 'Code Execution'
};

// Get friendly tool description
function getToolDescription(toolName) {
    if (!toolName) return 'Unknown Tool';
    const lower = toolName.toLowerCase();
    return TOOL_DESCRIPTIONS[lower] || toolName.charAt(0).toUpperCase() + toolName.slice(1);
}

// Helper to parse recent log entries with rich detail
function parseRecentLogs(maxEntries = 100) {
    const logFile = getTodayLogFile();
    const activities = [];

    try {
        if (!fs.existsSync(logFile)) {
            return activities;
        }

        const stats = fs.statSync(logFile);
        const size = stats.size;
        const bufferSize = Math.min(size, 262144); // 256KB for more history
        const buffer = Buffer.alloc(bufferSize);
        const fd = fs.openSync(logFile, 'r');
        fs.readSync(fd, buffer, 0, bufferSize, Math.max(0, size - bufferSize));
        fs.closeSync(fd);

        const content = buffer.toString('utf-8');
        const lines = content.split('\n').filter(l => l.trim());

        for (let i = lines.length - 1; i >= 0 && activities.length < maxEntries; i--) {
            try {
                if (i === 0 && size > bufferSize) continue;

                const parsed = JSON.parse(lines[i]);
                const meta = parsed._meta || {};

                let message = '';
                let level = meta.logLevelName?.toLowerCase() || 'info';
                let detail = null;
                let type = 'info';
                let sessionId = null;

                const data = parsed['1'];
                
                // Also check for structured data in other fields
                const toolData = parsed['2'] || {};
                const contextData = parsed['3'] || {};

                if (typeof data === 'string') {
                    // Extract session ID if present
                    const sessionMatch = data.match(/sessionId=([^\s]+)/);
                    sessionId = sessionMatch ? sessionMatch[1] : null;

                    // Tool start - extract specific tool parameters
                    if (data.includes('embedded run tool start')) {
                        const toolMatch = data.match(/tool=(\w+)/);
                        const toolName = toolMatch ? toolMatch[1] : 'unknown';
                        
                        // Parse tool-specific parameters
                        let toolDetail = '';
                        
                        if (toolName === 'exec' || toolName === 'process') {
                            const cmdMatch = data.match(/command[=:]"?([^"]{1,200})"?/) || 
                                           data.match(/cmd[=:]"?([^"]{1,200})"?/);
                            if (cmdMatch) {
                                toolDetail = cmdMatch[1].trim();
                                message = `exec: ${toolDetail}`;
                            } else {
                                message = `exec: <command>`;
                            }
                        } else if (toolName === 'read' || toolName === 'Read') {
                            const pathMatch = data.match(/path[=:]"?([^"\s]{1,150})"?/) ||
                                            data.match(/file[=:]"?([^"\s]{1,150})"?/);
                            if (pathMatch) {
                                toolDetail = pathMatch[1];
                                message = `read: ${toolDetail}`;
                            } else {
                                message = `read: <file>`;
                            }
                        } else if (toolName === 'write' || toolName === 'Write') {
                            const pathMatch = data.match(/path[=:]"?([^"\s]{1,150})"?/) ||
                                            data.match(/file[=:]"?([^"\s]{1,150})"?/);
                            if (pathMatch) {
                                toolDetail = pathMatch[1];
                                message = `write: ${toolDetail}`;
                            } else {
                                message = `write: <file>`;
                            }
                        } else if (toolName === 'edit' || toolName === 'Edit') {
                            const pathMatch = data.match(/path[=:]"?([^"\s]{1,150})"?/);
                            if (pathMatch) {
                                toolDetail = pathMatch[1];
                                message = `edit: ${toolDetail}`;
                            } else {
                                message = `edit: <file>`;
                            }
                        } else if (toolName === 'browser') {
                            const actionMatch = data.match(/action[=:]"?(\w+)"?/);
                            const urlMatch = data.match(/url[=:]"?([^"\s]{1,100})"?/);
                            const action = actionMatch ? actionMatch[1] : 'action';
                            const url = urlMatch ? urlMatch[1] : '';
                            if (url) {
                                message = `browser: ${action} ${url}`;
                            } else {
                                message = `browser: ${action}`;
                            }
                        } else if (toolName === 'web_fetch') {
                            const urlMatch = data.match(/url[=:]"?([^"\s]{1,100})"?/);
                            if (urlMatch) {
                                message = `web_fetch: ${urlMatch[1]}`;
                            } else {
                                message = `web_fetch: <url>`;
                            }
                        } else if (toolName === 'sessions_spawn') {
                            const taskMatch = data.match(/task[=:]"?([^"]{1,100})"?/) ||
                                            data.match(/label[=:]"?([^"]{1,100})"?/);
                            if (taskMatch) {
                                message = `spawn: ${taskMatch[1]}`;
                            } else {
                                message = `spawn: <subagent>`;
                            }
                        } else if (toolName === 'tts' || toolName === 'whisper' || toolName === 'transcribe') {
                            const textMatch = data.match(/text[=:]"?([^"]{1,80})"?/);
                            if (textMatch) {
                                message = `${toolName}: "${textMatch[1]}..."`;
                            } else {
                                message = `${toolName}: audio processing`;
                            }
                        } else if (toolName === 'image') {
                            const promptMatch = data.match(/prompt[=:]"?([^"]{1,80})"?/);
                            const pathMatch = data.match(/image[=:]"?([^"\s]{1,100})"?/);
                            if (promptMatch) {
                                message = `image: ${promptMatch[1]}`;
                            } else if (pathMatch) {
                                message = `image: ${pathMatch[1]}`;
                            } else {
                                message = `image: analysis`;
                            }
                        } else {
                            // Generic tool
                            const toolDesc = getToolDescription(toolName);
                            message = `${toolName}: started`;
                            
                            // Try to extract any input parameter
                            const inputMatch = data.match(/input[=:]"?([^"]{1,100})"?/);
                            if (inputMatch) {
                                toolDetail = inputMatch[1].replace(/\\n/g, ' ').trim();
                            }
                        }
                        
                        type = 'tool';
                        level = 'info';
                        detail = toolDetail || null;
                    }
                    // Tool end - show result preview
                    else if (data.includes('embedded run tool end')) {
                        const toolMatch = data.match(/tool=(\w+)/);
                        const toolName = toolMatch ? toolMatch[1] : 'unknown';
                        const durationMatch = data.match(/durationMs=(\d+)/);
                        const duration = durationMatch ? `${(parseInt(durationMatch[1]) / 1000).toFixed(1)}s` : '';
                        
                        // Check if it was an error
                        const errorMatch = data.match(/error[=:]"?([^"]{1,100})"?/);
                        if (errorMatch) {
                            message = `${toolName}: failed`;
                            detail = errorMatch[1];
                            level = 'error';
                        } else {
                            message = `${toolName}: completed${duration ? ` (${duration})` : ''}`;
                            level = 'success';
                        }
                        type = 'tool_complete';
                    }
                    // Whisper/transcription detection
                    else if (data.includes('whisper') || data.includes('transcrib') || data.includes('audio processing')) {
                        const textMatch = data.match(/text[=:]"?([^"]{1,150})"?/) ||
                                        data.match(/transcript[=:]"?([^"]{1,150})"?/);
                        if (textMatch) {
                            message = `Transcription`;
                            detail = `"${textMatch[1]}"`;
                            type = 'transcription';
                            level = 'success';
                        } else {
                            message = `Audio processing`;
                            type = 'transcription';
                            level = 'info';
                        }
                    }
                    // Run start - show model and channel with user message
                    else if (data.includes('embedded run start')) {
                        const modelMatch = data.match(/model=([^\s]+)/);
                        const channelMatch = data.match(/messageChannel=(\w+)/);
                        const thinkingMatch = data.match(/thinking=(\w+)/);
                        const runIdMatch = data.match(/runId=([^\s]+)/);

                        const model = modelMatch ? modelMatch[1] : 'unknown';
                        const channel = channelMatch ? channelMatch[1] : '';
                        const thinking = thinkingMatch ? thinkingMatch[1] : 'off';
                        const runId = runIdMatch ? runIdMatch[1] : null;

                        let channelLabel = channel ? ` via ${channel.charAt(0).toUpperCase() + channel.slice(1)}` : '';
                        
                        // Try to get the triggering message from the session transcript
                        let triggerText = null;
                        if (sessionId) {
                            try {
                                const sessionsFile = getSessionsFile();
                                if (sessionsFile && fs.existsSync(sessionsFile)) {
                                    const sessions = JSON.parse(fs.readFileSync(sessionsFile, 'utf-8'));
                                    
                                    // Find the session entry by searching for matching sessionId
                                    let sessionEntry = null;
                                    for (const [key, data] of Object.entries(sessions)) {
                                        if (data.sessionId === sessionId) {
                                            sessionEntry = data;
                                            break;
                                        }
                                    }
                                    
                                    if (sessionEntry && sessionEntry.sessionFile) {
                                        let transcriptPath = sessionEntry.sessionFile;
                                        if (!fs.existsSync(transcriptPath)) {
                                            transcriptPath = transcriptPath.replace('.clawdbot', '.moltbot');
                                        }
                                        if (!fs.existsSync(transcriptPath)) {
                                            transcriptPath = sessionEntry.sessionFile.replace('.moltbot', '.clawdbot');
                                        }
                                        
                                        if (fs.existsSync(transcriptPath)) {
                                            const transcript = fs.readFileSync(transcriptPath, 'utf-8');
                                            const transcriptLines = transcript.trim().split('\n').filter(l => l.trim());
                                            
                                            // Read backwards to find most recent user message
                                            for (let j = transcriptLines.length - 1; j >= Math.max(0, transcriptLines.length - 10); j--) {
                                                try {
                                                    const entry = JSON.parse(transcriptLines[j]);
                                                    const msg = entry.message || entry;
                                                    
                                                    if (msg.role === 'user' && msg.content) {
                                                        if (Array.isArray(msg.content)) {
                                                            for (const block of msg.content) {
                                                                if (block.type === 'text' && block.text) {
                                                                    // Extract the actual user text, removing meta info
                                                                    let text = block.text;
                                                                    // Remove [Telegram ...] prefix if present
                                                                    text = text.replace(/^\[.*?\]\s*/, '');
                                                                    // Remove [message_id: ...] suffix if present
                                                                    text = text.replace(/\s*\[message_id:.*?\]\s*$/, '');
                                                                    triggerText = text.trim().substring(0, 200);
                                                                    break;
                                                                }
                                                            }
                                                        } else if (typeof msg.content === 'string') {
                                                            triggerText = msg.content.substring(0, 200);
                                                        }
                                                        if (triggerText) break;
                                                    }
                                                } catch (e) { /* skip */ }
                                            }
                                        }
                                    }
                                }
                            } catch (e) {
                                // Silently fail
                            }
                        }
                        
                        // Check if this is a sub-agent by looking at sessionId
                        let agentLabel = null;
                        if (sessionId && sessionId.includes('subagent')) {
                            // Try to get label from sessions.json
                            const sessions = getActiveSessions();
                            const session = sessions.find(s => s.sessionId === sessionId);
                            if (session && session.label) {
                                agentLabel = session.label;
                            }
                        }

                        message = `Request started: ${model}${channelLabel}`;
                        if (agentLabel) {
                            message += ` [${agentLabel}]`;
                        }
                        type = 'request_start';
                        level = 'info';

                        // Build detail string with available context
                        let detailParts = [];
                        if (triggerText) {
                            detailParts.push(`"${triggerText}"`);
                        }
                        if (thinking && thinking !== 'none' && thinking !== 'off') {
                            detailParts.push(`Reasoning: ${thinking}`);
                        }
                        if (detailParts.length > 0) {
                            detail = detailParts.join(' • ');
                        }
                    }
                    // Run done - show duration and token usage
                    else if (data.includes('embedded run done')) {
                        const durationMatch = data.match(/durationMs=(\d+)/);
                        const abortedMatch = data.match(/aborted=(true|false)/);
                        const inputTokensMatch = data.match(/inputTokens=(\d+)/);
                        const outputTokensMatch = data.match(/outputTokens=(\d+)/);

                        const duration = durationMatch ? (parseInt(durationMatch[1]) / 1000).toFixed(1) : '?';
                        const aborted = abortedMatch && abortedMatch[1] === 'true';
                        const inputTokens = inputTokensMatch ? parseInt(inputTokensMatch[1]) : 0;
                        const outputTokens = outputTokensMatch ? parseInt(outputTokensMatch[1]) : 0;

                        if (aborted) {
                            message = `Request aborted after ${duration}s`;
                            level = 'warning';
                        } else {
                            message = `Request completed in ${duration}s`;
                            level = 'success';
                        }
                        type = 'request_complete';

                        if (inputTokens || outputTokens) {
                            detail = `Tokens: ${inputTokens} in / ${outputTokens} out`;
                        }
                    }
                    // User message received
                    else if (data.includes('received message') || data.includes('user message') || data.includes('incoming message')) {
                        const textMatch = data.match(/text="([^"]{1,300})"/);
                        const fromMatch = data.match(/from=(\w+)/);
                        const from = fromMatch ? fromMatch[1] : 'user';

                        if (textMatch) {
                            message = `Message from ${from}`;
                            detail = textMatch[1].replace(/\\n/g, ' ').substring(0, 200);
                            type = 'user_message';
                            level = 'info';
                        }
                    }
                    // Bot/Agent response
                    else if (data.includes('sending message') || data.includes('bot response') || data.includes('assistant message')) {
                        const textMatch = data.match(/text="([^"]+)"/) || data.match(/content="([^"]+)"/);
                        const toMatch = data.match(/to=(\w+)/);

                        if (textMatch) {
                            message = `Response sent`;
                            detail = textMatch[1].replace(/\\n/g, ' ').substring(0, 300);
                            type = 'bot_response';
                            level = 'success';
                        }
                    }
                    // Thinking/Reasoning content
                    else if (data.includes('thinking content') || data.includes('reasoning') || data.includes('chain of thought') || data.includes('embedded thinking')) {
                        const thinkingMatch = data.match(/content="([^"]+)"/) || data.match(/thinking="([^"]+)"/);
                        if (thinkingMatch) {
                            message = `Reasoning`;
                            detail = thinkingMatch[1].replace(/\\n/g, ' ').substring(0, 400);
                            type = 'thinking';
                            level = 'info';
                        }
                    }
                    // Session state changes
                    else if (data.includes('session state')) {
                        const prevMatch = data.match(/prev=(\w+)/);
                        const newMatch = data.match(/new=(\w+)/);
                        const reasonMatch = data.match(/reason="([^"]+)"/);

                        const prev = prevMatch ? prevMatch[1] : '';
                        const newState = newMatch ? newMatch[1] : '';
                        const reason = reasonMatch ? reasonMatch[1] : '';

                        if (newState === 'processing') {
                            message = `Session processing`;
                            type = 'state';
                        } else if (newState === 'idle' && reason === 'run_completed') {
                            message = `Session idle`;
                            type = 'state';
                        } else {
                            message = `State: ${prev} -> ${newState}`;
                            type = 'state';
                        }
                        level = 'info';
                    }
                    // API/Model calls
                    else if (data.includes('calling model') || data.includes('api call') || data.includes('llm request')) {
                        const modelMatch = data.match(/model=([^\s]+)/);
                        const model = modelMatch ? modelMatch[1] : 'API';
                        message = `Calling ${model}`;
                        type = 'api_call';
                        level = 'info';
                    }
                    // Lane task errors
                    else if (data.includes('lane task error') || data.includes('error')) {
                        const errorMatch = data.match(/error="([^"]+)"/);
                        const error = errorMatch ? errorMatch[1] : '';
                        if (error) {
                            message = `Error`;
                            detail = error.substring(0, 200);
                            type = 'error';
                            level = 'error';
                        }
                    }
                    // Telegram/WhatsApp messages
                    else if (data.includes('starting provider')) {
                        const botMatch = data.match(/\(([^)]+)\)/);
                        const bot = botMatch ? botMatch[1] : 'provider';
                        message = `Channel connected: ${bot}`;
                        type = 'connection';
                        level = 'success';
                    }
                    // Memory/context operations
                    else if (data.includes('memory') || data.includes('context')) {
                        const opMatch = data.match(/operation=(\w+)/);
                        const op = opMatch ? opMatch[1] : 'operation';
                        message = `Memory: ${op}`;
                        type = 'memory';
                        level = 'info';
                    }
                    // Skip noisy entries
                    else if (data.includes('heartbeat') || data.includes('status --json') || data.includes('ping')) {
                        continue;
                    }
                }

                if (message && message.length > 2) {
                    activities.push({
                        timestamp: meta.date || parsed.time || new Date().toISOString(),
                        message: message,
                        detail: detail,
                        type: type,
                        level: level,
                        sessionId: sessionId
                    });
                }
            } catch (e) {}
        }
    } catch (error) {
        console.error('Error reading logs:', error);
    }

    return activities;
}

let cachedClawStatus = null;
let lastCacheTime = 0;
const CACHE_TTL = 5000; // 5 seconds for more real-time feel
// Check both possible session file locations, prefer the one with newer data
const SESSIONS_PATHS = [
    path.join(os.homedir(), '.moltbot/agents/main/sessions/sessions.json'),
    path.join(os.homedir(), '.clawdbot/agents/main/sessions/sessions.json')
];

function getSessionsFile() {
    let bestPath = null;
    let bestMtime = 0;

    for (const p of SESSIONS_PATHS) {
        try {
            if (fs.existsSync(p)) {
                const stats = fs.statSync(p);
                if (stats.mtimeMs > bestMtime) {
                    bestMtime = stats.mtimeMs;
                    bestPath = p;
                }
            }
        } catch (e) {}
    }

    return bestPath || SESSIONS_PATHS[0];
}

// Get active session IDs from recent logs
function getActiveSessionsFromLogs() {
    const activeSessions = new Map();
    const now = Date.now();

    try {
        const logFile = getTodayLogFile();
        if (!fs.existsSync(logFile)) return activeSessions;

        const stats = fs.statSync(logFile);
        const size = stats.size;
        const bufferSize = Math.min(size, 131072); // 128KB
        const buffer = Buffer.alloc(bufferSize);
        const fd = fs.openSync(logFile, 'r');
        fs.readSync(fd, buffer, 0, bufferSize, Math.max(0, size - bufferSize));
        fs.closeSync(fd);

        const content = buffer.toString('utf-8');
        const lines = content.split('\n').filter(l => l.trim());

        // Look for session state changes in recent logs
        for (let i = lines.length - 1; i >= 0; i--) {
            try {
                const parsed = JSON.parse(lines[i]);
                const meta = parsed._meta || {};
                const logTime = new Date(meta.date || parsed.time).getTime();
                const data = parsed['1'] || '';

                // Only consider entries from last 60 seconds
                if (now - logTime > 60000) continue;

                if (typeof data === 'string') {
                    // Check for session state changes
                    if (data.includes('session state')) {
                        const sessionMatch = data.match(/sessionId=([^\s]+)/);
                        const stateMatch = data.match(/new=(\w+)/);
                        if (sessionMatch && stateMatch) {
                            const sessionId = sessionMatch[1];
                            const state = stateMatch[1];
                            if (!activeSessions.has(sessionId)) {
                                activeSessions.set(sessionId, { state, time: logTime });
                            }
                        }
                    }
                    // Check for run starts (processing)
                    else if (data.includes('embedded run start')) {
                        const sessionMatch = data.match(/sessionId=([^\s]+)/);
                        if (sessionMatch) {
                            activeSessions.set(sessionMatch[1], { state: 'processing', time: logTime });
                        }
                    }
                    // Check for run ends (idle)
                    else if (data.includes('embedded run done') || data.includes('run_completed')) {
                        const sessionMatch = data.match(/sessionId=([^\s]+)/);
                        if (sessionMatch && !activeSessions.has(sessionMatch[1])) {
                            activeSessions.set(sessionMatch[1], { state: 'idle', time: logTime });
                        }
                    }
                }
            } catch (e) {}
        }
    } catch (error) {
        console.error('Error parsing logs for active sessions:', error);
    }

    return activeSessions;
}

// Get Moltbot session data
function getMoltbotSessions() {
    const now = Date.now();
    if (cachedClawStatus && (now - lastCacheTime < CACHE_TTL)) {
        return cachedClawStatus;
    }

    try {
        // Get active states from logs
        const activeStates = getActiveSessionsFromLogs();

        // Read sessions directly from file (check both .moltbot and .clawdbot)
        const sessionsFile = getSessionsFile();
        if (sessionsFile && fs.existsSync(sessionsFile)) {
            const rawData = fs.readFileSync(sessionsFile, 'utf-8');
            const sessionData = JSON.parse(rawData);

            // Convert to array format
            const sessions = Object.entries(sessionData).map(([key, data]) => {
                const sessionId = data.sessionId || key;
                const activeInfo = activeStates.get(sessionId);

                // Determine state: check logs first, then check if recently updated
                let state = 'idle';
                if (activeInfo && activeInfo.state) {
                    state = activeInfo.state;
                } else if (data.updatedAt && (now - data.updatedAt < 30000)) {
                    state = 'active';
                } else if (data.updatedAt && (now - data.updatedAt < 300000)) {
                    state = 'idle'; // Updated within 5 min
                } else {
                    state = 'idle';
                }

                // Get total tokens - use totalTokens field directly, it's the cumulative count
                const totalTokens = data.totalTokens || data.total_tokens ||
                                   ((data.inputTokens || 0) + (data.outputTokens || 0)) || 0;

                // Get message count - count lines in session file if available
                let messageCount = data.messageCount || data.message_count || data.messages?.length || data.turns || 0;
                if (messageCount === 0 && data.sessionFile) {
                    try {
                        // Normalize path - check both .moltbot and .clawdbot locations
                        let sessionFilePath = data.sessionFile;
                        if (!fs.existsSync(sessionFilePath)) {
                            sessionFilePath = sessionFilePath.replace('.clawdbot', '.moltbot');
                        }
                        if (!fs.existsSync(sessionFilePath)) {
                            sessionFilePath = data.sessionFile.replace('.moltbot', '.clawdbot');
                        }
                        if (fs.existsSync(sessionFilePath)) {
                            const content = fs.readFileSync(sessionFilePath, 'utf-8');
                            messageCount = content.split('\n').filter(line => line.trim()).length;
                        }
                    } catch (e) {
                        // Ignore errors reading session file
                    }
                }

                // Get model - check multiple possible field names
                const model = data.skillsSnapshot?.model ||
                              data.model ||
                              data.modelOverride ||
                              data.currentModel ||
                              data.config?.model ||
                              'unknown';

                // Get createdAt - check field, then file birthtime, then fall back to updatedAt
                let createdAt = data.createdAt || data.created_at;
                if (!createdAt && data.sessionFile) {
                    try {
                        let sessionFilePath = data.sessionFile;
                        if (!fs.existsSync(sessionFilePath)) {
                            sessionFilePath = sessionFilePath.replace('.clawdbot', '.moltbot');
                        }
                        if (!fs.existsSync(sessionFilePath)) {
                            sessionFilePath = data.sessionFile.replace('.moltbot', '.clawdbot');
                        }
                        if (fs.existsSync(sessionFilePath)) {
                            const stats = fs.statSync(sessionFilePath);
                            createdAt = stats.birthtimeMs || stats.ctimeMs;
                        }
                    } catch (e) {
                        // Ignore errors
                    }
                }
                if (!createdAt) {
                    createdAt = data.updatedAt || data.updated_at || data.lastUpdate;
                }

                return {
                    key: key,
                    sessionId: sessionId,
                    updatedAt: data.updatedAt || data.updated_at || data.lastUpdate,
                    createdAt: createdAt,
                    model: model,
                    totalTokens: totalTokens,
                    contextTokens: data.contextTokens || data.context_tokens || 0,
                    messageCount: messageCount,
                    state: state,
                    channel: data.channel || data.lastChannel || data.source || 'unknown'
                };
            });

            cachedClawStatus = { sessions };
            lastCacheTime = now;
            return cachedClawStatus;
        }

        return cachedClawStatus || { sessions: [] };
    } catch (error) {
        console.error('Error reading sessions:', error);
        return cachedClawStatus || { sessions: [] };
    }
}

// API endpoint to get complete status
function getStatus() {
    const activities = parseRecentLogs(40);
    const memory = getMemoryUsage();
    const cpu = getCpuUsage();
    const gatewayProcess = getGatewayProcessStats();
    const sessionData = getMoltbotSessions();
    
    // Add recent assistant messages from current session transcript
    try {
        const mainSessionPath = getSessionsFile();
        if (mainSessionPath && fs.existsSync(mainSessionPath)) {
            const sessions = JSON.parse(fs.readFileSync(mainSessionPath, 'utf-8'));
            const mainSession = sessions['agent:main:main'];
            if (mainSession && mainSession.sessionFile) {
                const assistantMessages = getRecentAssistantMessages(mainSession.sessionFile, 3);
                assistantMessages.forEach(msg => {
                    activities.push({
                        timestamp: new Date(msg.timestamp).toISOString(),
                        message: 'Assistant reply',
                        detail: msg.text,
                        type: 'assistant',
                        level: 'success'
                    });
                });
            }
        }
    } catch (e) {
        // Silently fail
    }
    
    // Sort activities by timestamp descending
    activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Process session data
    let activeSessions = [];
    let totalSessions = 0;
    let agentSessions = 0;
    let currentSession = null;
    
    if (sessionData && sessionData.sessions) {
        totalSessions = sessionData.sessions.length;
        
        sessionData.sessions.forEach(session => {
            const sessionInfo = {
                key: session.key || session.id,
                label: session.label || session.key?.split(':').pop() || 'unnamed',
                status: session.state && session.state !== 'null' ? session.state : 'idle',
                model: session.model || 'unknown',
                tokens: session.totalTokens || 0,
                messages: session.messageCount || 0,
                updated: formatTime(session.updatedAt),
                created: formatTime(session.createdAt),
                isAgent: session.key?.includes('agent:')
            };
            
            activeSessions.push(sessionInfo);
            
            if (sessionInfo.isAgent) {
                agentSessions++;
            }
            
            // Most recently updated session is "current"
            if (!currentSession || new Date(session.updatedAt) > new Date(currentSession.updatedAt)) {
                currentSession = sessionInfo;
            }
        });
    }
    
    // Detect reasoning/thinking from logs
    let reasoning = false;
    try {
        const logFile = getTodayLogFile();
        if (fs.existsSync(logFile)) {
            const stats = fs.statSync(logFile);
            const size = stats.size;
            const bufferSize = Math.min(size, 131072); // 128KB
            const buffer = Buffer.alloc(bufferSize);
            const fd = fs.openSync(logFile, 'r');
            fs.readSync(fd, buffer, 0, bufferSize, Math.max(0, size - bufferSize));
            fs.closeSync(fd);
            const content = buffer.toString('utf-8');
            const lines = content.split('\n');

            for (let i = lines.length - 1; i >= 0; i--) {
                if (lines[i].includes('embedded run start')) {
                    try {
                        const parsed = JSON.parse(lines[i]);
                        const logData = parsed['1'] || {};
                        if (typeof logData === 'string' && logData.includes('thinking=')) {
                            reasoning = !logData.includes('thinking=none') && !logData.includes('thinking=off');
                        }
                        break;
                    } catch (e) {}
                }
            }
        }
    } catch (e) {}
    
    let currentTask = null;
    if (activities.length > 0) {
        // Find the most recent meaningful activity for the "Current Task" display
        // We look for activities from the last 2 minutes
        const now = Date.now();
        const meaningfulRecent = activities.find(a => {
            const age = now - new Date(a.timestamp).getTime();
            if (age > 120000) return false; // Ignore anything older than 2 mins

            // Prioritize specific activity types (including assistant replies)
            return a.type === 'assistant' ||
                   a.type === 'tool' || 
                   a.type === 'thinking' || 
                   a.type === 'transcription' ||
                   a.type === 'user_message';
        });

        if (meaningfulRecent) {
            let taskDesc = meaningfulRecent.message;
            if (meaningfulRecent.detail) {
                // Show preview of detail for assistant replies and tools
                const preview = meaningfulRecent.detail.substring(0, 80);
                taskDesc = `${meaningfulRecent.message}: ${preview}${meaningfulRecent.detail.length > 80 ? '...' : ''}`;
            }
            currentTask = { 
                description: taskDesc,
                type: meaningfulRecent.type,
                timestamp: meaningfulRecent.timestamp
            };
        } else {
            // Check if we just completed something
            const completed = activities.find(a => {
                const age = now - new Date(a.timestamp).getTime();
                return age < 30000 && (a.type === 'request_complete' || a.type === 'bot_response' || a.type === 'assistant');
            });
            
            if (completed) {
                currentTask = { description: 'Waiting for user...', type: 'idle' };
            } else {
                currentTask = { description: 'Idle', type: 'idle' };
            }
        }
    } else {
        currentTask = { description: 'Idle', type: 'idle' };
    }
    
    const isProcessing = activities.length > 0 && 
        (Date.now() - new Date(activities[0].timestamp).getTime() < 30000);
    
    return {
        // Current session info
        session: currentSession?.key || 'none',
        sessionLabel: currentSession?.label || 'idle',
        model: currentSession?.model || 'none',
        reasoning,
        processing: isProcessing,
        
        // Session stats
        totalSessions,
        agentSessions,
        activeSessions,
        
        // System info
        system: {
            cpu: cpu,
            memory: memory,
            host: os.hostname(),
            platform: `${os.type()} ${os.release()}`,
            arch: os.arch(),
            nodeVersion: process.version,
            uptime: os.uptime()
        },
        
        // Gateway info
        gateway: {
            address: '127.0.0.1:18789',
            process: gatewayProcess
        },
        
        // Activity
        activityLog: activities,
        currentTask,
        
        // Timestamp
        timestamp: new Date().toISOString()
    };
}

// Allowed static files whitelist (only serve these files)
const ALLOWED_STATIC_FILES = new Set([
    '/index.html',
    '/app.js',
    '/style.css'
]);

// HTTP server
const server = http.createServer((req, res) => {
    // Only allow same-origin requests (no CORS for cross-origin)
    // This prevents other websites from accessing the API
    const origin = req.headers.origin;
    if (origin) {
        // Only allow requests from the same host
        const host = req.headers.host;
        const originHost = new URL(origin).host;
        if (host === originHost) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        }
    }

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // Parse URL and prevent path traversal
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const urlPath = path.normalize(parsedUrl.pathname);

    // Block path traversal attempts
    if (urlPath.includes('..') || !urlPath.startsWith('/')) {
        res.writeHead(403);
        res.end('403 Forbidden');
        return;
    }

    // Check authentication (skip for health endpoint)
    if (urlPath !== '/api/health' && !checkAuth(req, res)) {
        sendUnauthorized(res);
        return;
    }

    if (urlPath === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(getStatus()));
        return;
    }

    if (urlPath === '/api/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', timestamp: Date.now() }));
        return;
    }

    // Serve static files - only allow whitelisted files
    let filePath = urlPath === '/' ? '/index.html' : urlPath;

    if (!ALLOWED_STATIC_FILES.has(filePath)) {
        res.writeHead(404);
        res.end('404 Not Found');
        return;
    }

    const extname = path.extname(filePath);
    const contentTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css'
    };
    const contentType = contentTypes[extname] || 'text/plain';

    fs.readFile(path.join(__dirname, filePath), (err, content) => {
        if (err) {
            res.writeHead(404);
            res.end('404 Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`✓ MAX Dashboard running on http://0.0.0.0:${PORT}`);
    console.log(`✓ System monitoring enabled`);
    console.log(`✓ Molt.bot session tracking enabled`);

    const authToken = getAuthToken();
    if (AUTH_DISABLED) {
        console.log(`⚠ Authentication DISABLED (MAX_DASHBOARD_NO_AUTH=true)`);
    } else if (authToken) {
        console.log(`✓ Authentication enabled (using Molt.bot auth token)`);
    } else {
        console.log(`⚠ No auth token found - authentication disabled`);
    }
});
