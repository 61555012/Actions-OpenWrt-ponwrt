/* oaf-lite protocol distribution tab.
 * Six legend classes, matching the sampler's PROTO_* enum and colours:
 *   TLS(yellow) HTTP(orange) QUIC(green) FAILED(red) DNS(dark red) OTHER(blue)
 * Data: /cgi-bin/luci/admin/status/oaf_users/api/proto_traffic?mac=...
 *
 * The chart is a 24-hour stacked bar (same shape as the detail page's
 * "今日常用 APP" chart): x = hour buckets 00:00..23:00, one stacked series per
 * protocol, colour from the sampler's proto.json "order" map. Each protocol
 * entry may carry an "h" map {hour -> {up, down}} written by the C sampler;
 * when it is missing (old sampler still running) we fall back to a single
 * current-hour stack built from the per-protocol totals.
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

	/* The detail page declares FWX_NARROW / FWX_ECHART_RENDERER as top-level
	 * `const` in an inline script that loads AFTER this file. A direct
	 * reference from inside a callback is resolved at call time (already
	 * initialised), but wrap in try/catch so a standalone include is safe. */
	function narrow() {
		try { return !!FWX_NARROW; } catch (e) { return false; }
	}
	function rendererName() {
		try { return FWX_ECHART_RENDERER || 'canvas'; } catch (e) { return 'canvas'; }
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

		var rows = [], total = 0;
		order.forEach(function (o) {
			var r = byName[o.name] || { up: 0, down: 0, h: {} };
			var v = (Number(r.up) || 0) + (Number(r.down) || 0);
			total += v;
			rows.push({
				name: o.name,
				color: o.color || '#3B82F6',
				up: Number(r.up) || 0,
				down: Number(r.down) || 0,
				bytes: v,
				h: r.h || {}
			});
		});

		var legend = document.getElementById('proto_legend');
		if (legend) {
			legend.innerHTML = rows.map(function (r) {
				var pct = total > 0 ? (r.bytes * 100 / total).toFixed(1) : '0.0';
				var wd = total > 0 ? Math.max(1, r.bytes * 100 / total) : 0;
				return '<div class="proto-legend-row">'
					+ '<span class="proto-legend-dot" style="background:' + esc(r.color) + '"></span>'
					+ '<span class="proto-legend-name">' + esc(r.name) + '</span>'
					+ '<span class="proto-legend-meta">' + fmt(r.bytes) + ' <span class="pct">' + pct + '%</span></span>'
					+ '<span class="proto-legend-bar"><i style="width:' + wd.toFixed(1) + '%;background:' + esc(r.color) + '"></i></span>'
					+ '</div>';
			}).join('') || '<div class="proto-note" style="opacity:.6;">暂无数据</div>';
		}

		// summary cards
		var elTotal = document.getElementById('proto_total');
		if (elTotal) elTotal.textContent = fmt(total);
		var elKinds = document.getElementById('proto_kinds');
		if (elKinds) {
			var n = rows.filter(function (r) { return r.bytes > 0; }).length;
			elKinds.textContent = n + ' / ' + rows.length;
		}

		var box = document.getElementById('proto_chart');
		if (!box || !w.echarts) return;
		if (!chart) chart = w.echarts.init(box, null, { renderer: rendererName() });
		var text = dark() ? '#e5e7eb' : '#374151';
		var sub = dark() ? '#9ca3af' : '#6b7280';
		var isNarrow = narrow();

		// 24 hourly buckets, same axis as the APP / traffic charts on the page.
		var hours = [], hi;
		for (hi = 0; hi < 24; hi++) hours.push((hi < 10 ? '0' + hi : hi) + ':00');

		// Detect whether the sampler already emits per-hour data. Old binaries
		// (or the first page load right after an upgrade) only carry totals;
		// fold those into the current hour so the chart is never blank.
		var hasHours = rows.some(function (r) {
			for (var k in r.h) if (Object.prototype.hasOwnProperty.call(r.h, k)) {
				var c = r.h[k] || {};
				if ((Number(c.up) || 0) + (Number(c.down) || 0) > 0) return true;
			}
			return false;
		});
		var nowHour = (new Date()).getHours();

		var series = rows.map(function (r) {
			var data = [];
			for (hi = 0; hi < 24; hi++) {
				if (hasHours) {
					var cell = r.h[String(hi)] || r.h[hi] || {};
					var up = Number(cell.up) || 0;
					var down = Number(cell.down) || 0;
					data.push({ value: up + down, up: up, down: down });
				} else {
					data.push(hi === nowHour
						? { value: r.bytes, up: r.up, down: r.down }
						: { value: 0, up: 0, down: 0 });
				}
			}
			return {
				name: r.name,
				type: 'bar',
				stack: 'proto',
				data: data,
				barWidth: isNarrow ? 12 : 20,
				barMaxWidth: isNarrow ? 18 : 30,
				itemStyle: { color: r.color },
				emphasis: { focus: 'series' }
			};
		});

		chart.setOption({
			backgroundColor: 'transparent',
			animation: !isNarrow,
			title: {
				text: '今日协议流量（24 小时）',
				subtext: '合计 ' + fmt(total),
				left: 'center', top: 2,
				textStyle: { color: text, fontSize: 14, fontWeight: 'normal' },
				subtextStyle: { color: sub, fontSize: 12 }
			},
			tooltip: {
				trigger: 'axis',
				axisPointer: { type: 'shadow' },
				formatter: function (params) {
					if (!params || !params.length) return '';
					var res = esc(params[0].axisValue || params[0].name || '') + '<br/>';
					var hourTotal = 0, shown = 0;
					params.forEach(function (p) {
						var v = Number(p.value) || 0;
						if (!v) return;
						hourTotal += v;
						shown++;
						var it = p.data || {};
						res += p.marker + esc(p.seriesName) + ': ' + fmt(v)
							+ ' <span style="opacity:.65">(' + fmt(it.up || 0) + ' / ' + fmt(it.down || 0) + ')</span><br/>';
					});
					if (!shown) return '';
					return res + '时段合计 <b>' + fmt(hourTotal) + '</b>';
				}
			},
			legend: {
				// On phones the ECharts scroll legend squeezes six colour chips
				// into one row and they overlap each other / the axis labels.
				// The HTML "协议构成" card below already renders the full legend
				// (dot + name + bytes + bar), so hide the built-in one on narrow
				// screens and give the chart area more bottom room instead.
				show: !isNarrow,
				data: rows.map(function (r) { return r.name; }),
				bottom: 0,
				type: 'scroll',
				orient: 'horizontal',
				left: 'center',
				textStyle: { color: text, fontSize: 12 },
				itemWidth: 14, itemHeight: 10, itemGap: 14
			},
			grid: {
				left: '1%', right: '1%', top: '18%',
				bottom: isNarrow ? '8%' : '19%',
				containLabel: true
			},
			xAxis: {
				type: 'category',
				data: hours,
				axisLabel: {
					color: text,
					rotate: isNarrow ? 0 : 45,
					interval: isNarrow ? 3 : 0,
					fontSize: isNarrow ? 10 : 11
				},
				axisLine: { lineStyle: { color: text } }
			},
			yAxis: {
				type: 'value',
				name: isNarrow ? '' : '流量',
				nameTextStyle: { color: sub },
				axisLabel: {
					color: text,
					formatter: function (v) { return fmt(v); }
				},
				axisLine: { lineStyle: { color: text } },
				splitLine: {
					lineStyle: { color: dark() ? 'rgba(255,255,255,.1)' : 'rgba(0,0,0,.08)' }
				}
			},
			series: series
		}, true);
		chart.resize();
	}

	function loadInfo() {
		get(apiPath('sampler_info'), function (d) {
			var el = document.getElementById('proto_sampler_info');
			var be = document.getElementById('proto_backend');
			if ((!el && !be) || !d) return;
			if (be) be.textContent = Number(d.degraded) ? '估算' : (d.backend || 'conntrack');
			if (el) el.innerHTML = '<div class="proto-note">采样器 oaf-lite ' + esc(d.version || '')
				+ '<br/>规则 ' + (Number(d.feature_rules) || 0) + ' 条 · 明文特征库'
				+ '<br/>' + (Number(d.degraded)
					? '<span style="color:#E5484D">估算模式：仅含首包可采样流量</span>'
					: '后端：' + esc(d.backend || '-')) + '</div>';
		});
	}

	function active() {
		// Protocol distribution was merged into the "Today Traffic" tab.
		// Only poll / redraw while that tab (or the embedded proto section) is visible.
		var host = document.getElementById('tab-traffic-statistics');
		var sect = document.getElementById('tab-protocol');
		var hostOn = host && host.classList.contains('active');
		var sectOn = !sect || sect.classList.contains('active') ||
			!(sect.classList.contains('tab-body')); // embedded section is always "on" with its host
		return !!(hostOn && sectOn);
	}

	/* Explain the OTHER slice: list the dominant (proto/port) contributors so a
	 * large blue wedge is no longer a black box. On closed-HNAT boxes most
	 * offloaded traffic never shows a first packet, so it lands here. */
	function renderOther(d) {
		var el = document.getElementById('proto_other_note');
		var card = document.getElementById('proto_other_card');
		if (!el) return;
		var top = d.other_top || [];
		if (!top.length) {
			if (card) card.style.display = 'none';
			el.innerHTML = '';
			return;
		}
		if (card) card.style.display = '';
		el.innerHTML = top.map(function (o) {
			return '<div class="proto-other-row">'
				+ '<span class="proto-other-port">' + esc(o.proto) + '/' + esc(o.port) + '</span>'
				+ '<span>' + fmt(Number(o.bytes) || 0) + '</span>'
				+ '</div>';
		}).join('') + '<div class="proto-note" style="margin-top:6px;">未携带可识别首包特征的端口流量归入「其他」（多为硬件卸载流）。</div>';
	}

	/* Closed HNAT (e.g. XG040 vendor hw_nat) does not write offloaded byte
	 * counters back into conntrack, so the chart only reflects pre-offload and
	 * non-offloaded traffic. Say so plainly instead of looking broken. */
	function renderHwNote(d) {
		if (!Number(d.hw_offload_unreliable)) return;
		var el = document.getElementById('proto_sampler_info');
		if (!el) return;
		if (el.innerHTML.indexOf('硬件加速') < 0) {
			el.innerHTML += '<div class="proto-note" style="color:#E5484D;margin-top:6px;">硬件加速流量未回写 conntrack，本图为估算值。</div>';
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

	/* The host page calls this when the "Today Traffic" tab becomes visible:
	 * an ECharts instance created while its container was display:none has
	 * zero width, so it must be resized after the tab is shown. */
	w.oafProtoResize = function () { if (chart) { try { chart.resize(); } catch (e) {} } };

	w.addEventListener('resize', function () { if (chart && active()) chart.resize(); });
	w.addEventListener('oaf-theme-change', function () { if (lastData && active()) render(lastData); });
})(window);
