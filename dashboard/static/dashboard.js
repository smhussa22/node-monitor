// node-monitor dashboard — chart and stream helpers
// kept in one file because the dashboard is small enough that splitting modules adds friction

// fetch sparkline data for every visible device in one request, then render tiny line charts inline
async function renderSparklines() {

    const canvases = document.querySelectorAll("canvas.sparkline");
    if (canvases.length === 0) return;

    let data;
    try {
        const r = await fetch("/api/devices/sparklines");
        data = await r.json();
    } catch (e) {
        return;
    }

    canvases.forEach((canvas) => {
        const host = canvas.dataset.host;
        const field = canvas.dataset.field;
        const series = data[host];
        if (!series || series.length === 0) return;

        // series rows are [ts, cpu, memory]; pick the right index for this field
        const idx = field === "cpu" ? 1 : 2;
        const points = series.map((row) => row[idx]);
        const labels = series.map(() => "");

        new Chart(canvas, {
            type: "line",
            data: {
                labels,
                datasets: [{
                    data: points,
                    borderColor: field === "cpu" ? "#dc3545" : "#0d6efd",
                    borderWidth: 1.2,
                    pointRadius: 0,
                    tension: 0.3,
                    fill: false,
                }],
            },
            options: {
                responsive: false,
                animation: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                scales: {
                    x: { display: false },
                    y: { display: false, min: 0, max: 100 },
                },
                elements: { line: { borderJoinStyle: "round" } },
            },
        });
    });

}


// pull the full cpu/memory history for one host and render a labeled line chart
async function renderHistoryChart(hostname, window) {

    const canvas = document.getElementById("history-chart");
    if (!canvas) return;

    const r = await fetch(`/api/devices/${encodeURIComponent(hostname)}/history?window=${window}`);
    const points = await r.json();

    const labels = points.map((p) => new Date(p.ts).toLocaleTimeString());
    const cpu = points.map((p) => p.cpu);
    const mem = points.map((p) => p.memory);

    new Chart(canvas, {
        type: "line",
        data: {
            labels,
            datasets: [
                { label: "cpu",    data: cpu, borderColor: "#dc3545", backgroundColor: "rgba(220,53,69,0.08)", fill: true,  tension: 0.25, pointRadius: 0 },
                { label: "memory", data: mem, borderColor: "#0d6efd", backgroundColor: "rgba(13,110,253,0.08)", fill: true, tension: 0.25, pointRadius: 0 },
            ],
        },
        options: {
            responsive: true,
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { position: "top" } },
            scales: {
                y: { min: 0, max: 100, title: { display: true, text: "percent" } },
                x: { ticks: { maxTicksLimit: 12 } },
            },
        },
    });

}


// donut chart of netflow protocol breakdown
function renderProtocolChart(protocols) {

    const canvas = document.getElementById("protocol-chart");
    if (!canvas || protocols.length === 0) return;

    new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: protocols.map((p) => p.protocol),
            datasets: [{
                data: protocols.map((p) => p.flows),
                backgroundColor: ["#0d6efd", "#dc3545", "#198754", "#ffc107", "#6c757d"],
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { position: "right" }, title: { display: true, text: "flows by protocol" } },
        },
    });

}


// gantt-style incident timeline backed by vis-timeline
function renderIncidentTimeline(incidents) {

    const container = document.getElementById("timeline");
    if (!container || incidents.length === 0) return;

    const severityClass = { critical: "vis-critical", warning: "vis-warning", info: "vis-info" };
    const items = incidents.map((inc, i) => ({
        id: i,
        group: inc.host,
        start: inc.start,
        end: inc.end,
        content: `${inc.rule}`,
        title: `${inc.rule} on ${inc.host} (${inc.severity})`,
        className: severityClass[inc.severity] || "",
    }));

    const hosts = [...new Set(incidents.map((i) => i.host))].sort();
    const groups = hosts.map((h) => ({ id: h, content: h }));

    new vis.Timeline(container, new vis.DataSet(items), new vis.DataSet(groups), {
        stack: true,
        zoomable: true,
        margin: { item: 6 },
        orientation: "top",
    });

    // inject severity colors used by vis classnames above
    const css = document.createElement("style");
    css.textContent = `
        .vis-critical { background: #dc3545 !important; border-color: #b02a37 !important; color: white !important; }
        .vis-warning  { background: #ffc107 !important; border-color: #cc9a06 !important; color: #212529 !important; }
        .vis-info     { background: #0dcaf0 !important; border-color: #0aa1c0 !important; color: #212529 !important; }
    `;
    document.head.appendChild(css);

}


// server-sent-events feed for the live page
function startLiveStream() {

    const status = document.getElementById("live-status");
    const feed = document.getElementById("live-feed");
    const counter = document.getElementById("live-count");
    if (!status || !feed) return;

    const healthClass = {
        healthy:  "bg-success",
        degraded: "bg-warning text-dark",
        down:     "bg-danger",
    };

    let count = 0;
    const source = new EventSource("/api/live/stream");

    source.onopen = () => { status.textContent = "live"; status.className = "badge bg-success"; };
    source.onerror = () => { status.textContent = "disconnected"; status.className = "badge bg-danger"; };

    source.onmessage = (event) => {
        const m = JSON.parse(event.data);
        const tr = document.createElement("tr");
        tr.className = "new";
        const health = m.health_status || "unknown";
        tr.innerHTML = `
            <td class="small">${m.ts ? new Date(m.ts).toLocaleTimeString() : ""}</td>
            <td><a href="/devices/${encodeURIComponent(m.hostname)}">${m.hostname}</a></td>
            <td>${m.vendor}</td>
            <td>${m.cpu.toFixed(1)}</td>
            <td>${m.memory.toFixed(1)}</td>
            <td><span class="badge ${healthClass[health] || 'bg-secondary'}">${health}</span></td>
        `;
        feed.insertBefore(tr, feed.firstChild);

        // cap feed length so the dom stays light
        while (feed.children.length > 100) feed.removeChild(feed.lastChild);
        count += 1;
        counter.textContent = count;
    };

}
