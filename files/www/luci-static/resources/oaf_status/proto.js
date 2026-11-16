/* oaf-lite protocol distribution tab.
 * Six legend classes, matching the sampler's PROTO_* enum and colours:
 *   TLS(yellow) HTTP(orange) QUIC(green) FAILED(red) DNS(dark red) OTHER(blue)
 * Data: /cgi-bin/luci/admin/status/oaf_users/api/proto_traffic?mac=...
 */
(function (w) {
	'use strict';

	var chart = null;
	var timer = null;
	var lastData = null;

	function mac() {
		var m = '';
		/* The detail page already resolves ?mac= (and the /detail/<mac> form)
		 * into a global `mac` and exposes getUrlParameter(); prefer those over
		 * re-parsing, so older browsers without URLSearchParams still work. */
		if (typeof w.getUrlParameter === 'function') {
			try { m = w.getUrlParameter('mac') || ''; } catch (e) {}
		}
		if (!m && typeof w.mac === 'string') m = w.mac;
		if (!m && w.URLSearchParams) {
			try { m = new w.URLSearchParams(w.location.search).get('mac') || ''; } catch (e) {}
		}
		if (!m) {
			var el = document.getElementById('device-title-mac');
			if (el) m = (el.textContent || '').trim();
		}
		if (m && m !== '--') {
			try { m = decodeURIComponent(m); } catch (e) {}
		}
		return m === '--' ? '' : m;
	}

	function apiPath(name) {
		var base = w.location.pathname.replace(/\/+$/, '').replace(/\/detail$/, '');
		return base + '/api/' + name;
	}

	function fmt(v) {
		v = Number(v) || 0;
		if (v < 1024) return v.toFixed(0) + ' B';
		var u = ['KB', 'MB', 'GB', 'TB'], i = -1;
		do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
		return v.toFixed(v >= 100 ? 0 : (v >= 10 ? 1 : 2)) + ' ' + u[i];
	}

	function esc(s) {
		return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
		});
	}

	function dark() {
		return document.documentElement.getAttribute('data-darkmode') === 'true';
	}

	function get(url, cb) {
		if (w.jQuery && w.jQuery.getJSON) {
			w.jQuery.getJSON(url, cb).fail(function () { cb(null); });
			return;
		}
		try {
			var x = new XMLHttpRequest();
			x.open('GET', url, true);
			x.onreadystatechange = function () {
				if (x.readyState !== 4) return;
				try { cb(x.status === 200 ? JSON.parse(x.responseText) : null); }
				catch (e) { cb(null); }
			};
			x.send();
		} catch (e) { cb(null); }
	}

	function render(d) {
		if (!d) return;
		lastData = d;
		var order = d.order || [];
		var list = d.list || [];
		var byName = {};
		list.forEach(function (r) { byName[r.name] = r; });

		renderOther(d);
		renderHwNote(d);

		var series = [], total = 0, rows = [];
		order.forEach(function (o) {
			var r = byName[o.name] || { up: 0, down: 0 };
			var v = (Number(r.up) || 0) + (Number(r.down) || 0);
			total += v;
			series.push({
				name: o.name, value: v,
				itemStyle: { color: o.color || '#3B82F6' }
			});
			rows.push({ name: o.name, color: o.color || '#3B82F6', up: r.up, down: r.down, bytes: v });
		});

		var legend = document.getElementById('proto_legend');
		if (legend) {
			legend.innerHTML = rows.map(function (r) {
				var pct = total > 0 ? (r.bytes * 100 / total).toFixed(1) : '0.0';
				return '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(128,128,128,.15);">'
					+ '<span style="width:11px;height:11px;border-radius:2px;flex:none;background:' + esc(r.color) + '"></span>'
					+ '<span style="flex:1;font-size:13px;">' + esc(r.name) + '</span>'
					+ '<span style="font-size:12px;opacity:.75;">' + fmt(r.bytes) + ' · ' + pct + '%</span>'
					+ '</div>';
			}).join('') || '<div style="opacity:.6;font-size:12px;">暂无数据</div>';
		}

		var box = document.getElementById('proto_chart');
		if (!box || !w.echarts) return;
		if (!chart) chart = w.echarts.init(box, null, { renderer: 'canvas' });
		var text = dark() ? '#e5e7eb' : '#374151';
		var sub = dark() ? '#9ca3af' : '#6b7280';
		chart.setOption({
			backgroundColor: 'transparent',
			tooltip: {
				trigger: 'item',
				formatter: function (p) {
					var r = rows[p.dataIndex] || {};
					return esc(p.name) + '<br/>合计 ' + fmt(p.value)
						+ '<br/>上行 ' + fmt(r.up) + ' / 下行 ' + fmt(r.down)
						+ '<br/>占比 ' + p.percent + '%';
				}
			},
			legend: { show: false },
			title: {
				text: '今日协议流量', subtext: '合计 ' + fmt(total),
				left: 'center', top: '42%',
				textStyle: { color: text, fontSize: 14, fontWeight: 'normal' },
				subtextStyle: { color: sub, fontSize: 12 }
			},
			series: [{
				type: 'pie', radius: ['48%', '70%'], center: ['50%', '50%'],
				avoidLabelOverlap: true, startAngle: 90,
				label: { show: true, color: text, fontSize: 11,
					formatter: '{b}\n{d}%' },
				labelLine: { length: 8, length2: 8, lineStyle: { color: sub } },
				itemStyle: { borderColor: dark() ? '#1f2937' : '#ffffff', borderWidth: 2 },
				data: series
			}]
		}, true);
		chart.resize();
	}

	function loadInfo() {
		get(apiPath('sampler_info'), function (d) {
			var el = document.getElementById('proto_sampler_info');
			if (!el || !d) return;
			el.innerHTML = '采样器 oaf-lite ' + esc(d.version || '')
				+ '<br/>规则 ' + (Number(d.feature_rules) || 0) + ' 条 · 明文特征库'
				+ '<br/>后端：' + esc(d.backend || '-')
				+ (Number(d.degraded) ? '<br/><span style="color:#E5484D">估算模式</span>' : '');
		});
	}

	function active() {
		var t = document.getElementById('tab-protocol');
		return t && t.classList.contains('active');
	}

	/* Explain the OTHER slice: list the dominant (proto/port) contributors so a
	 * large blue wedge is no longer a black box. On closed-HNAT boxes most
	 * offloaded traffic never shows a first packet, so it lands here. */
	function renderOther(d) {
		var el = document.getElementById('proto_other_note');
		if (!el) return;
		var top = d.other_top || [];
		if (!top.length) { el.innerHTML = ''; return; }
		var rows = top.map(function (o) {
			return '<div style="display:flex;gap:8px;padding:3px 0;">'
				+ '<span style="opacity:.7;width:88px;flex:none;">'
				+ esc(o.proto) + '/' + esc(o.port) + '</span>'
				+ '<span style="flex:1;">' + fmt(Number(o.bytes) || 0) + '</span>'
				+ '</div>';
		}).join('');
		el.innerHTML = '<div style="font-weight:bold;margin-bottom:4px;">其他（OTHER）构成</div>'
			+ rows
			+ '<div style="margin-top:6px;opacity:.7;">以上端口流量未携带可识别的 TLS/HTTP/QUIC/DNS 首包特征，归入「其他」。</div>';
	}

	/* Closed HNAT (e.g. XG040 vendor hw_nat) does not write offloaded byte
	 * counters back into conntrack, so the chart only reflects pre-offload and
	 * non-offloaded traffic. Say so plainly instead of looking broken. */
	function renderHwNote(d) {
		if (!Number(d.hw_offload_unreliable)) return;
		var el = document.getElementById('proto_sampler_info');
		if (!el) return;
		if (el.innerHTML.indexOf('硬件加速') < 0) {
			el.innerHTML += '<br/><span style="color:#E5484D">硬件加速流量未回写 conntrack，本图为估算值（仅含首包可采样流量）</span>';
		}
	}

	w.loadProtoTraffic = function () {
		var m = mac();
		if (!m) return;
		get(apiPath('proto_traffic') + '?mac=' + encodeURIComponent(m), render);
		loadInfo();
		if (!timer) {
			timer = setInterval(function () {
				if (active()) w.loadProtoTraffic();
			}, 15000);
		}
	};

	w.addEventListener('resize', function () { if (chart && active()) chart.resize(); });
	w.addEventListener('oaf-theme-change', function () { if (lastData && active()) render(lastData); });
})(window);
