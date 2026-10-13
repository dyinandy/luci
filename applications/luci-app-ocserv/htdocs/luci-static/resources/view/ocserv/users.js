'use strict';
'require form';
'require fs';
'require ui';
'require rpc';

/* OpenConnect VPN JavaScript for LuCI 
   Converted from Lua to JavaScript by @systemcrash
   Copyright 2014 Nikos Mavrogiannopoulos <n.mavrogiannopoulos@gmail.com>
   Licensed to the public under the Apache License 2.0.
*/

const callRcInit = rpc.declare({
	object: 'rc',
	method: 'init',
	params: [ 'name', 'action' ],
});

return L.view.extend({
	load() {
		return Promise.all([
			L.resolveDefault(fs.exec('/usr/bin/occtl', ['--json', 'show', 'users']).then(res => res.stdout), ''),
			L.uci.load('ocserv'),
		]);
	},

	parseUsers(output) {
		const users = [];
		
		// Handle empty or invalid output
		if (!output || !output.trim()) {
			return users;
		}

		try {
			const json = JSON.parse(output.trim());
			
			let userList = [];
			if (Array.isArray(json)) {
				userList = json;
			} else if (json && Array.isArray(json.users)) {
				userList = json.users;
			} else if (typeof json === 'object' && json !== null) {
				userList = Object.values(json);
			}

			return userList.map(entry => this.normalizeUser(entry));
		} catch (e) {
			console.error('Failed to parse occtl JSON output:', e.message, output);
			return users;
		}
	},

	normalizeUser(entry) {
		if (!entry || typeof entry !== 'object') return {};
		const getProp = (obj, ...keys) => {
			for (const key of keys) {
				if (obj[key] !== undefined && obj[key] !== null && obj[key] !== '') {
					return obj[key];
				}
			}
			const objKeys = Object.keys(obj);
			for (const targetKey of keys) {
				const normalizedTarget = targetKey.toLowerCase().replace(/[-_ ]/g, '');
				const foundKey = objKeys.find(k => k.toLowerCase().replace(/[-_ ]/g, '') === normalizedTarget);
				if (foundKey && obj[foundKey] !== undefined && obj[foundKey] !== null && obj[foundKey] !== '') {
					return obj[foundKey];
				}
			}
			return null;
		};

		// Get user ID
		const id = getProp(entry, 'ID', 'id', 'Id') ?? '-';

		// Get User name info
		const rawUser = getProp(entry, 'Username', 'username', 'user', 'User', 'CN', 'cn', 'cert-user', 'tls-auth');
		const displayUser = rawUser ? String(rawUser) : (id !== '-' ? `(Cert User #${id})` : _('Certificate User'));

		// Get IP info
		const vpn_ip = getProp(entry, 'IPv4', 'vpn-ipv4', 'vpn_ip', 'vpn-ip', 'VPN IPv4', 'VPN IP') || '-';
		const vpn_ip6 = getProp(entry, 'IPv6', 'vpn-ipv6', 'vpn_ip6', 'vpn-ip6', 'VPN IPv6') || '-';
		const remote_ip = getProp(entry, 'Remote IP', 'remote-ip', 'ip', 'IP', 'RemoteIP', 'remote_ip') || '-';

		// Get Device info
		const device = getProp(entry, 'Device', 'device', 'dev', 'Interface', 'interface') || '-';

		// Get time infor
		const time = getProp(entry, 'Connected at', 'connected-at', 'Last connected at', 'connected_at', 'time', 'Time', '_time') || '-';

		let rawCipher = getProp(
			entry, 
			'Cipher', 'cipher', 'Ciphers', 'Cipher suite', 'cipher-suite', 'cipher_suite',
			'TLS', 'DTLS', 'DTLS cipher', 'tls-cipher', 'dtls-cipher', 'tls_cipher', 'dtls_cipher'
		);

		let cipherStr = '';
		if (typeof rawCipher === 'object' && rawCipher !== null) {
			const tls = rawCipher.tls || rawCipher.TLS || '';
			const dtls = rawCipher.dtls || rawCipher.DTLS || '';
			cipherStr = dtls || tls || JSON.stringify(rawCipher);
		} else if (rawCipher) {
			cipherStr = String(rawCipher);
		} else {
			const dtls = getProp(entry, 'DTLS', 'dtls', 'dtls-cipher');
			const tls = getProp(entry, 'TLS', 'tls', 'tls-cipher');
			cipherStr = dtls || tls || '-';
		}

		if (cipherStr && cipherStr !== '-') {
			const matches = cipherStr.match(/\(([^)]+)\)/g);
			if (matches && matches.length > 0) {
				const lastMatch = matches[matches.length - 1];
				cipherStr = lastMatch.replace(/[()]/g, '').trim();
			} else {
				const parts = cipherStr.split(/[-/]/);
				if (parts.length > 2 && /GCM|CBC|POLY1305|AES|CHACHA/i.test(parts[parts.length - 1])) {
					cipherStr = parts.slice(-2).join('-');
				}
			}
		}

		// Get State & Group info
		const status = getProp(entry, 'State') || 'active';
		const group = getProp(entry, 'Groupname') || 'default';

		// Get tx and rx
		const tx = getProp(entry, '_TX') || 'n/a';
		const rx = getProp(entry, '_RX') || 'n/a';

		return {
			id: id,
			user: displayUser,
			group: group,
			vpn_ip: vpn_ip,
			vpn_ip6: vpn_ip6,
			ip: remote_ip,
			device: device,
			time: time,
			cipher: cipherStr || '-',
			status: status,
			tx: tx,
			rx: rx
		};
	},

	handleDisconnect(id, ev) {
		return L.resolveDefault(
			fs.exec('/usr/bin/occtl', ['disconnect', 'id', id]),
			null
		).then(() => {
			L.ui.addNotification(null, E('p', _('User %s has been disconnected.').format(id)), 'info');
			// Reload the page to refresh the user list
			window.location.reload();
		}).catch(function(e) {
			L.ui.addNotification(null, E('p', _('Failed to disconnect user: %s').format(e.message)), 'error');
		});
	},

	render([occtl_output]) {
		const users = this.parseUsers(occtl_output);
		const auth_method = L.uci.get('ocserv', 'config', 'auth');

		const m = new form.Map('ocserv', _('OpenConnect VPN'));

		// If using plain authentication, show user management section
		if (auth_method === 'plain') {
			const s = m.section(form.TableSection, 'ocservusers', _('Available users'));
			s.anonymous = true;
			s.addremove = true;

			let o;

			o = s.option(form.Value, 'name', _('Name'));
			o.rmempty = false;
			o.datatype = 'uciname';

			o = s.option(form.DummyValue, 'group', _('Group'));
			o.rmempty = true;

			o = s.option(form.Value, 'password', _('Password'));
			o.password = true;
			o.rmempty = false;
			
			// Custom write to handle password encryption
			o.write = function(section_id, formvalue) {
				// Check if password is already hashed (starts with $)
				if (formvalue.match(/^\$\d+\$/)) {
					return form.Value.prototype.write.call(this, section_id, formvalue);
				} else {
					// For new passwords, we'll store them as-is and let ocserv handle hashing
					// In production, you might want to hash client-side or via RPC
					return form.Value.prototype.write.call(this, section_id, formvalue);
				}
			};
		}

		// Active Users section
		const activeSection = m.section(form.TypedSection, '__active_users__', _('Active users'));
		activeSection.anonymous = true;
		activeSection.cfgsections = function() { return ['_active']; };

		// Use a custom render to display active users table
		activeSection.render = L.bind(function() {
			const table = E('div', { 'class': 'table cbi-section-table' }, [
				E('div', { 'class': 'tr table-titles' }, [
					E('div', { 'class': 'th' }, _('ID')),
					E('div', { 'class': 'th' }, _('Username')),
					E('div', { 'class': 'th' }, _('Group')),
					E('div', { 'class': 'th' }, _('VPN IPv4')),
					E('div', { 'class': 'th' }, _('VPN IPv6')),
					E('div', { 'class': 'th' }, _('Remote IP')),
					E('div', { 'class': 'th' }, _('Device')),
					E('div', { 'class': 'th' }, _('Time')),
					E('div', { 'class': 'th' }, _('Cipher')),
					E('div', { 'class': 'th' }, _('Status')),
					E('div', { 'class': 'th' }, _('Tx')),
					E('div', { 'class': 'th' }, _('Rx')),
					E('div', { 'class': 'th cbi-section-actions' }, _('Actions'))
				])
			]);

			if (users.length === 0) {
				table.appendChild(
					E('div', { 'class': 'tr placeholder' }, [
						E('div', { 'class': 'td', 'style': 'grid-column: 1 / -1; text-align: center;' },
							E('em', _('There are no active users.')))
					])
				);
			} else {
				for (let user of users) {
					table.appendChild(
						E('div', { 'class': 'tr' }, [
							E('div', { 'class': 'td', 'data-title': _('ID') }, user.id),
							E('div', { 'class': 'td', 'data-title': _('Username') }, user.user),
							E('div', { 'class': 'td', 'data-title': _('Group') }, user.group),
							E('div', { 'class': 'td', 'data-title': _('VPN IPv4') }, user.vpn_ip),
							E('div', { 'class': 'td', 'data-title': _('VPN IPv6') }, user.vpn_ip6),
							E('div', { 'class': 'td', 'data-title': _('Remote IP') }, user.ip),
							E('div', { 'class': 'td', 'data-title': _('Device') }, user.device),
							E('div', { 'class': 'td', 'data-title': _('Time') }, user.time),
							E('div', { 'class': 'td', 'data-title': _('Cipher') }, user.cipher),
							E('div', { 'class': 'td', 'data-title': _('Status') }, user.status),
							E('div', { 'class': 'td', 'data-title': _('Tx') }, user.tx),
							E('div', { 'class': 'td', 'data-title': _('Rx') }, user.rx),
							E('div', { 'class': 'td cbi-section-actions' }, 
								E('button', {
									'class': 'cbi-button cbi-button-remove',
									'click': L.bind(this.handleDisconnect, this, user.id)
								}, _('Disconnect')))
						])
					);
				}
			}

			return E('div', { 'class': 'cbi-section' }, [
				E('h3', _('Active users')),
				table
			]);
		}, this);

		return m.render();
	},

	// handleSave(ev) {
	// 	return this.super('handleSave', [ev]).then(() => {
	// 		// Restart ocserv after user changes
	// 		return callRcInit('ocserv', 'restart');
	// 	}).then(() => {
	// 		L.ui.addNotification(null, E('p', _('Configuration saved and ocserv restarted.')), 'info');
	// 	}).catch(function(e) {
	// 		L.ui.addNotification(null, E('p', _('Failed to restart ocserv: %s').format(e.message)), 'error');
	// 	});
	// }
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

});
