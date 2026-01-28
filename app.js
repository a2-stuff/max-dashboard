// Max Dashboard v4.0 - Futuristic Real-time Monitoring
class MaxDashboard {
    constructor() {
        this.updateInterval = 2000;
        this.pollTimer = null;
        this.isConnected = false;
        this.cpuHistory = [];
        this.maxHistoryPoints = 20;
        this.init();
    }

    init() {
        document.getElementById('clearLogBtn').addEventListener('click', () => {
            this.clearActivityLog();
        });

        this.startPolling();
        this.fetchData();
    }

    startPolling() {
        if (this.pollTimer) clearInterval(this.pollTimer);
        this.pollTimer = setInterval(() => this.fetchData(), this.updateInterval);
    }

    async fetchData() {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();

            if (!this.isConnected) {
                this.setConnectionStatus(true);
                this.isConnected = true;
            }

            this.updateSystemResources(data.system);
            this.updateAgentsList(data.activeSessions);
            this.updateCurrentStatus(data);
            this.updateActivityLog(data.activityLog);
            this.updateTimestamp(data.timestamp);
            this.updateSessionCount(data);

        } catch (error) {
            console.error('Fetch error:', error);
            if (this.isConnected) {
                this.setConnectionStatus(false);
                this.isConnected = false;
            }
        }
    }

    setConnectionStatus(connected) {
        const dot = document.getElementById('connectionDot');
        const ping = document.getElementById('connectionPing');
        const text = document.getElementById('connectionText');

        if (connected) {
            dot.classList.remove('bg-red-500');
            dot.classList.add('bg-secondary');
            ping.classList.remove('bg-red-500');
            ping.classList.add('bg-secondary');
            text.textContent = 'Connected';
        } else {
            dot.classList.remove('bg-secondary');
            dot.classList.add('bg-red-500');
            ping.classList.remove('bg-secondary');
            ping.classList.add('bg-red-500');
            text.textContent = 'Disconnected';
        }
    }

    updateSystemResources(system) {
        if (!system) return;

        // CPU
        const cpuValue = document.getElementById('cpuValue');
        const cpuBar = document.getElementById('cpuBar');
        if (system.cpu !== undefined) {
            cpuValue.textContent = `${system.cpu}%`;
            cpuBar.style.width = `${system.cpu}%`;
            this.updateCpuChart(system.cpu);
        }

        // Memory
        const memValue = document.getElementById('memValue');
        const memBar = document.getElementById('memBar');
        if (system.memory) {
            memValue.textContent = `${system.memory.percent}%`;
            memBar.style.width = `${system.memory.percent}%`;
        }

        // System info
        if (system.host) {
            document.getElementById('hostName').textContent = system.host;
        }
        if (system.uptime !== undefined) {
            document.getElementById('systemUptime').textContent = this.formatUptime(system.uptime);
        }
    }

    updateCpuChart(cpu) {
        this.cpuHistory.push(cpu);
        if (this.cpuHistory.length > this.maxHistoryPoints) {
            this.cpuHistory.shift();
        }

        const chartLine = document.getElementById('chartLine');
        const chartArea = document.getElementById('chartArea');
        if (!chartLine || !chartArea) return;

        const width = 400;
        const height = 100;
        const points = this.cpuHistory.length;
        const stepX = width / (this.maxHistoryPoints - 1);

        let linePath = '';
        let areaPath = '';

        this.cpuHistory.forEach((value, index) => {
            const x = index * stepX;
            const y = height - (value / 100 * height);

            if (index === 0) {
                linePath = `M${x},${y}`;
                areaPath = `M${x},${height} L${x},${y}`;
            } else {
                linePath += ` L${x},${y}`;
                areaPath += ` L${x},${y}`;
            }
        });

        // Close area path
        const lastX = (this.cpuHistory.length - 1) * stepX;
        areaPath += ` L${lastX},${height} Z`;

        chartLine.setAttribute('d', linePath);
        chartArea.setAttribute('d', areaPath);
    }

    updateAgentsList(sessions) {
        const container = document.getElementById('agentsList');
        const countEl = document.getElementById('totalSessions');

        if (!sessions || sessions.length === 0) {
            container.innerHTML = '<tr><td colspan="6" class="px-4 py-4 text-center text-slate-500 text-sm">No active agents</td></tr>';
            countEl.textContent = '0';
            return;
        }

        countEl.textContent = sessions.length;
        container.innerHTML = '';

        sessions.forEach(session => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors';

            const name = session.label || session.key?.split(':').pop() || 'unnamed';
            const isMain = name === 'main';
            const status = session.status || 'idle';
            const model = session.model?.split('/').pop() || 'unknown';
            const tokens = this.formatNumber(session.tokens || 0);
            const messages = session.messages || 0;
            const updated = session.updated || '--';

            // Status badge classes - bigger and more visible
            let statusClasses = 'border px-2 py-0.5 text-[10px] uppercase font-bold';
            if (status === 'active' || status === 'processing') {
                statusClasses += ' border-secondary/40 bg-secondary/15 text-secondary';
            } else {
                statusClasses += ' border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-500';
            }

            row.innerHTML = `
                <td class="px-4 py-2.5 ${isMain ? 'font-semibold text-slate-900 dark:text-slate-200' : 'text-slate-400'}">${name}</td>
                <td class="px-4 py-2.5"><span class="${statusClasses}">${status.toUpperCase()}</span></td>
                <td class="px-4 py-2.5 text-slate-500 hidden sm:table-cell">${model}</td>
                <td class="px-4 py-2.5 text-right font-medium">${tokens}</td>
                <td class="px-4 py-2.5 text-right text-slate-400 hidden md:table-cell">${messages}</td>
                <td class="px-4 py-2.5 text-right text-slate-500 hidden sm:table-cell">${updated}</td>
            `;

            container.appendChild(row);
        });
    }

    updateCurrentStatus(data) {
        // Session
        const activeSession = document.getElementById('activeSession');
        activeSession.textContent = data.sessionLabel || '--';

        // Model
        const currentModel = document.getElementById('currentModel');
        if (data.model) {
            currentModel.textContent = data.model.split('/').pop() || data.model;
        } else {
            currentModel.textContent = '--';
        }

        // Processing
        const processingStatus = document.getElementById('processingStatus');
        if (data.processing) {
            processingStatus.textContent = 'Active';
            processingStatus.className = 'px-2 py-0.5 text-[10px] font-bold bg-secondary/15 text-secondary uppercase border border-secondary/30';
        } else {
            processingStatus.textContent = 'Idle';
            processingStatus.className = 'px-2 py-0.5 text-[10px] font-bold bg-slate-200 dark:bg-slate-800 text-slate-500 uppercase border border-slate-300 dark:border-slate-700';
        }

        // Reasoning
        const reasoningStatus = document.getElementById('reasoningStatus');
        if (data.reasoning) {
            reasoningStatus.textContent = 'On';
            reasoningStatus.className = 'px-2 py-0.5 text-[10px] font-bold bg-secondary/15 text-secondary uppercase border border-secondary/30';
        } else {
            reasoningStatus.textContent = 'Off';
            reasoningStatus.className = 'px-2 py-0.5 text-[10px] font-bold bg-slate-200 dark:bg-slate-800 text-slate-500 uppercase border border-slate-300 dark:border-slate-700';
        }

        // Current task
        const currentTask = document.getElementById('currentTask');
        const taskIcon = document.getElementById('taskIcon');
        const taskWrapper = document.getElementById('currentTaskWrapper');

        if (data.currentTask?.description) {
            currentTask.textContent = data.currentTask.description;
            taskIcon.textContent = 'check_circle';
            taskWrapper.classList.remove('text-slate-400');
            taskWrapper.classList.add('text-secondary');
        } else {
            currentTask.textContent = 'Idle';
            taskIcon.textContent = 'hourglass_empty';
            taskWrapper.classList.remove('text-secondary');
            taskWrapper.classList.add('text-slate-400');
        }
    }

    updateActivityLog(activities) {
        if (!activities || !Array.isArray(activities) || activities.length === 0) {
            return;
        }

        const container = document.getElementById('activityLog');
        const countEl = document.getElementById('activityCount');

        // Update count
        if (countEl) {
            countEl.textContent = `${activities.length} events`;
        }

        // Check if newest activity changed
        const firstEntry = container.querySelector('[data-msg]');
        const newestMessage = activities[0]?.message + (activities[0]?.detail || '');

        if (firstEntry && firstEntry.getAttribute('data-msg') === newestMessage) {
            return;
        }

        // Rebuild log
        container.innerHTML = '';

        activities.slice(0, 50).forEach(activity => {
            const entry = document.createElement('div');
            entry.className = 'border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/[0.01] transition-colors';
            entry.setAttribute('data-msg', activity.message + (activity.detail || ''));

            const timestamp = new Date(activity.timestamp);
            const timeStr = timestamp.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });

            // Determine icon and color based on type/level
            let icon = 'info';
            let colorClass = 'text-slate-500 dark:text-slate-400';
            let bgClass = '';

            const type = activity.type || 'info';
            const level = activity.level || 'info';

            switch (type) {
                case 'tool':
                    icon = 'construction';
                    colorClass = 'text-primary';
                    break;
                case 'tool_complete':
                    icon = 'check_circle';
                    colorClass = 'text-secondary';
                    break;
                case 'request_start':
                    icon = 'play_circle';
                    colorClass = 'text-primary';
                    bgClass = 'bg-primary/5';
                    break;
                case 'request_complete':
                    icon = 'task_alt';
                    colorClass = 'text-secondary';
                    bgClass = 'bg-secondary/5';
                    break;
                case 'user_message':
                    icon = 'chat';
                    colorClass = 'text-blue-400';
                    bgClass = 'bg-blue-500/5';
                    break;
                case 'bot_response':
                    icon = 'smart_toy';
                    colorClass = 'text-purple-400';
                    bgClass = 'bg-purple-500/5';
                    break;
                case 'thinking':
                    icon = 'psychology';
                    colorClass = 'text-amber-400';
                    bgClass = 'bg-amber-500/5';
                    break;
                case 'state':
                    icon = 'sync';
                    colorClass = 'text-slate-400';
                    break;
                case 'api_call':
                    icon = 'cloud';
                    colorClass = 'text-cyan-400';
                    break;
                case 'error':
                    icon = 'error';
                    colorClass = 'text-red-500';
                    bgClass = 'bg-red-500/5';
                    break;
                case 'memory':
                    icon = 'memory';
                    colorClass = 'text-indigo-400';
                    break;
                case 'connection':
                    icon = 'link';
                    colorClass = 'text-secondary';
                    break;
                default:
                    if (level === 'error') {
                        icon = 'error';
                        colorClass = 'text-red-500';
                    } else if (level === 'warning') {
                        icon = 'warning';
                        colorClass = 'text-amber-500';
                    } else if (level === 'success') {
                        icon = 'check_circle';
                        colorClass = 'text-secondary';
                    }
            }

            // Build the entry HTML
            let detailHtml = '';
            if (activity.detail) {
                detailHtml = `
                    <div class="mt-1.5 ml-7 sm:ml-8 pl-3 border-l-2 border-slate-200 dark:border-slate-700">
                        <p class="text-xs sm:text-sm text-slate-500 dark:text-slate-400 font-mono break-all leading-relaxed">${this.escapeHtml(activity.detail)}</p>
                    </div>
                `;
            }

            entry.innerHTML = `
                <div class="px-3 sm:px-4 py-2.5 ${bgClass}">
                    <div class="flex items-start space-x-2 sm:space-x-3">
                        <span class="text-slate-500 shrink-0 text-[10px] sm:text-xs font-mono pt-0.5">${timeStr}</span>
                        <span class="material-symbols-outlined text-lg sm:text-xl ${colorClass} shrink-0">${icon}</span>
                        <div class="flex-1 min-w-0">
                            <span class="${colorClass} font-medium text-sm">${activity.message}</span>
                            ${activity.sessionId ? `<span class="text-[9px] sm:text-[10px] text-slate-500 ml-2 font-mono hidden sm:inline">${activity.sessionId.substring(0, 8)}...</span>` : ''}
                        </div>
                    </div>
                    ${detailHtml}
                </div>
            `;

            container.appendChild(entry);
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    clearActivityLog() {
        const container = document.getElementById('activityLog');
        const countEl = document.getElementById('activityCount');

        if (countEl) countEl.textContent = '0 events';

        container.innerHTML = `
            <div class="px-4 py-3 text-slate-500 text-center">
                <span class="material-symbols-outlined text-2xl mb-1 block opacity-30">delete_sweep</span>
                Log cleared
            </div>
        `;
    }

    updateTimestamp(timestamp) {
        const el = document.getElementById('lastUpdate');
        if (timestamp) {
            const date = new Date(timestamp);
            el.textContent = date.toLocaleTimeString('en-US', { hour12: false });
        }
    }

    updateSessionCount(data) {
        const el = document.getElementById('totalSessions');
        if (data.totalSessions !== undefined) {
            el.textContent = data.totalSessions;
        }
    }

    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    }

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new MaxDashboard();
});
