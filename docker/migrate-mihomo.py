#!/usr/bin/env python3
"""Create a reviewable, offline LemonVPN migration bundle from Mihomo JSON.

The source may contain credentials. No network requests or live configuration
changes are made. Existing output directories are never overwritten.
"""
import argparse
import base64
import json
import os
from pathlib import Path


def quoted(value):
    return json.dumps(value, ensure_ascii=False)


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def endpoint(value):
    if '://' in value:
        return value
    return 'udp://' + value + ('' if ':' in value else ':53')


def split_rule(text):
    depth = 0
    parts, start = [], 0
    for i, character in enumerate(text):
        if character == '(':
            depth += 1
        elif character == ')':
            depth -= 1
        elif character == ',' and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    tail = ',no-resolve' if parts[-1] == 'no-resolve' else ''
    if tail:
        parts.pop()
    target = parts.pop()
    return ','.join(parts) + tail, target


def convert(source, output, enhance_dns=False):
    nodes = source.get('proxies', [])
    groups = source.get('proxy-groups', [])
    if not nodes or not groups:
        raise ValueError('需要包含展开后的 proxies 和 proxy-groups')
    names = [item['name'] for item in nodes + groups]
    if len(set(names)) != len(names):
        raise ValueError('节点与组名称重复，请先消除歧义')
    helpers = {'DIRECT': '迁移直连', 'REJECT': '迁移拦截'}
    if any(v in names for v in helpers.values()):
        raise ValueError('内置出站辅助组名称已占用')
    def outbound(name):
        if name in helpers:
            return helpers[name]
        if name not in names:
            raise ValueError('引用了不存在的出站')
        return name

    entries = ['lemonvpn-providers 1', 'p migrated-inline inline - 3600 TGVtb25WUE4vMC4x 1 0 - ok - - - - -']
    for node in nodes:
        if node.get('dialer-proxy'):
            raise ValueError('节点自身包含 dialer-proxy，须显式迁移为链路')
        link = 'mihomo://' + encoded(json.dumps(node, ensure_ascii=False, separators=(',', ':')))
        entries.append('n ' + encoded(node['name']) + ' ' + encoded(link))
    text = ['# 从 Mihomo 展开配置迁移；原始凭据仅保存在 providers.conf。', 'group {']
    for name, target in [(helpers['DIRECT'], 'direct'), (helpers['REJECT'], 'block')]:
        text += [f'  {quoted(name)} {{', '    filter: !name(regex: ".*")', '    policy: select', f'    final: {target}', '  }']
    for group in groups:
        kind = group.get('type')
        members = [outbound(n) for n in group.get('proxies', [])]
        if not members or kind not in ['select', 'url-test', 'fallback', 'load-balance']:
            raise ValueError('存在未支持或未展开成员的策略组')
        policy = {'select': 'select', 'url-test': 'min_moving_avg', 'fallback': 'fallback', 'load-balance': 'roundrobin'}[kind]
        if kind != 'select' and any(n not in {x['name'] for x in nodes} for n in members):
            raise ValueError('自动组包含嵌套出站，须先确定等效选择策略')
        filters = ['outbound(' + ', '.join(map(quoted, members)) + ')'] if kind == 'select' else ['name(' + ', '.join(map(quoted, members)) + ')']
        text += [f'  {quoted(group["name"])} {{'] + ['    filter: ' + f for f in filters] + ['    policy: ' + policy, '  }']
    text += ['}', 'dns {', '  upstream {', "    default: 'udp://223.5.5.5:53'", '  }', '  routing {', '    request {', '      fallback: migrated-default', '    }', '    response {', '      upstream(migrated-default) && domain(geosite: gfw) -> migrated-fallback', '      upstream(migrated-default) && dip(cidr: 240.0.0.0/4) -> migrated-fallback', '      upstream(migrated-default) && qtype(A, AAAA) && !dip(geoip: cn) -> migrated-fallback', '      fallback: accept', '    }', '  }', '}', 'routing {']
    # Exclusions are address allocation rules, not routing rules. Preserve both.
    for domain in ['argotunnel.com', 'cftunnel.com']:
        text.append(f'  domain(suffix: {domain}) -> direct')
    for domain in ['install.lemon.vin', 'teamnode.lemon.vin']:
        text.append(f'  domain(full: {domain}) -> direct')

    document = {'schema': 1, 'providers': [], 'resolvers': [], 'pools': [], 'policies': [], 'bindings': [], 'cache': {'capacity': 4096, 'max_bytes': 16777216, 'negative': True, 'stale_seconds': 30, 'prefetch': True}, 'bootstrap': []}
    runs = []
    fallback = 'direct'
    for row in source.get('rules', []):
        condition, target = split_rule(row)
        target = {'DIRECT': 'direct', 'REJECT': 'block'}.get(target, target)
        if condition == 'MATCH':
            fallback = target
            continue
        if not runs or runs[-1][0] != target:
            runs.append((target, []))
        runs[-1][1].append(condition)
    for i, (target, rules) in enumerate(runs):
        identity = f'migrated-route-{i+1:02}'
        document['providers'].append({'id': identity, 'name': f'旧路由 {i+1:02} · {target}', 'source': 'inline', 'format': 'text', 'behavior': 'classical', 'content': '\n'.join(rules)})
        document['bindings'].append({'id': identity, 'name': f'旧顺序 {i+1:02}', 'condition': f'ruleset({identity})', 'outbound': target})
    text += ['  fallback: ' + quoted(fallback), '}']
    dns = source.get('dns', {})
    resolver_ids = {}
    def pool(identity, name, urls):
        members = []
        for url in urls:
            url = endpoint(url)
            if url not in resolver_ids:
                rid = f'migrated-resolver-{len(resolver_ids)+1:02}'
                resolver_ids[url] = rid
                document['resolvers'].append({'id': rid, 'name': url, 'url': url, 'outbound': 'direct', 'timeout_ms': 3000})
            members.append(resolver_ids[url])
        document['pools'].append({'id': identity, 'name': name, 'members': list(dict.fromkeys(members)), 'strategy': 'race'})
    pool('migrated-default', '默认解析 · 旧 nameserver', dns['nameserver'])
    pool('migrated-fallback', '境外备用 · 旧 fallback', dns['fallback'])
    document['pools'][0]['failover'] = 'migrated-fallback'
    for i, (condition, urls) in enumerate(dns.get('nameserver-policy', {}).items()):
        identity = f'migrated-dns-{i+1:02}'
        pool(identity, '解析策略 ' + condition, urls if isinstance(urls, list) else [urls])
        if condition.startswith('geosite:'):
            expression = 'domain(geosite: ' + quoted(condition[8:]) + ')'
        elif condition.startswith('+.'):
            expression = 'domain(suffix: ' + quoted(condition[2:]) + ')'
        elif '*' not in condition:
            expression = 'domain(full: ' + quoted(condition) + ')'
        else:
            raise ValueError('DNS 策略含未支持的域名模式')
        document['policies'].append({'id': identity, 'name': condition, 'condition': expression, 'pool': identity, 'address_mode': 'inherit'})
    # Explicit tunnel DNS exceptions must precede broad foreign classifications.
    tunnel_conditions = {f'domain(suffix: {quoted(domain)})' for domain in ['argotunnel.com', 'cftunnel.com']}
    for policy in document['policies']:
        if policy['condition'] in tunnel_conditions:
            policy['address_mode'] = 'real-ip'
    document['policies'].sort(key=lambda policy: policy['condition'] not in tunnel_conditions)
    document['bootstrap'] = [endpoint(s) for s in dns.get('default-nameserver', ['223.5.5.5'])]
    if enhance_dns:
        proxy = next(g['name'] for g in groups if g['type'] == 'select')
        ids = []
        for brand, host, ip in [('cloudflare', 'cloudflare-dns.com', '1.1.1.1'), ('google', 'dns.google', '8.8.8.8')]:
            identity = 'migration-doh-' + brand
            document['resolvers'].append({'id': identity, 'name': '境外 DoH · ' + brand, 'url': f'https://{host}/dns-query', 'bootstrap': [ip], 'outbound': proxy, 'timeout_ms': 8000})
            ids.append(identity)
        foreign = {p['pool'] for p in document['policies'] if 'geolocation-!cn' in p['condition']}
        for p in document['pools']:
            if p['id'] == 'migrated-fallback' or p['id'] in foreign:
                p['members'] = ids.copy()
                p['name'] = '境外加密解析 · ' + p['name']
    settings = {'mode': dns.get('enhanced-mode', 'fake-ip'), 'ipv4_range': dns.get('fake-ip-range', '198.18.0.1/16'), 'ipv6_range': '', 'filters': dns.get('fake-ip-filter', []), 'store_fake_ip': bool(source.get('profile', {}).get('store-fake-ip', True)), 'ipv6_enabled': bool(source.get('ipv6', True) and dns.get('ipv6', True)), 'sniff_enabled': bool(source.get('sniffer', {}).get('enable', False))}
    report = {'nodes': len(nodes), 'original_groups': len(groups), 'helper_groups': 2, 'original_rules': len(source.get('rules', [])), 'ordered_rule_sets': len(runs), 'dns_resolvers': len(document['resolvers']), 'dns_pools': len(document['pools']), 'dns_policies': len(document['policies']), 'fake_ip_exclusions': len(settings['filters']), 'notes': ['内联节点为配置快照；原订阅更新来源需要单独确认。', '旧自动选择转换为 LemonVPN 延迟策略，探测 URL/容差/间隔需人工复核。', '不迁移正在写入的 cache.db；跨版本映射恢复仍需一致性快照演练。', '未复制外部控制 API、宿主路由或防火墙，部署与切换单独处理。']}
    if enhance_dns:
        report['notes'].append('境外与故障备用解析改用策略代理上的 Cloudflare/Google DoH；国内与隧道例外保留原解析配置。')
    proxy = next(g['name'] for g in groups if g['type'] == 'select')
    geodata = {'settings': {kind: {'urls': [f'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/{kind}.dat', f'https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/{kind}.dat']} for kind in ['geoip', 'geosite']}, 'source_override': True}
    geodata['settings'].update({'download': {'route': 'group', 'group_id': 'group-' + proxy}, 'verify_checksum': True, 'auto_update': {'enabled': True, 'interval_hours': 24}})
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in {'geodata-settings.json': json.dumps(geodata, ensure_ascii=False, indent=2)+'\n', 'providers.conf': '\n'.join(entries)+'\n', 'config.dae': '\n'.join(text)+'\n', 'rules-document.json': json.dumps(document, ensure_ascii=False, indent=2)+'\n', 'dns-settings.json': json.dumps(settings, ensure_ascii=False, indent=2)+'\n', 'migration-report.json': json.dumps(report, ensure_ascii=False, indent=2)+'\n'}.items():
        file = output / name
        with file.open('x', encoding='utf-8') as stream:
            stream.write(data)
        os.chmod(file, 0o600)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_json', type=Path)
    parser.add_argument('new_output_directory', type=Path)
    parser.add_argument('--enhance-dns', action='store_true', help='境外及备用解析使用策略代理上的 DoH')
    args = parser.parse_args()
    report = convert(json.loads(args.source_json.read_text(encoding='utf-8')), args.new_output_directory, args.enhance_dns)
    print(json.dumps(report, ensure_ascii=False, indent=2))
