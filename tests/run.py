"""Run the test suites, each in its own user and network namespace."""

import argparse
import importlib
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness

SUITES = ('fw', 'routing', 'divert', 'integration')


def child(name, output):
    try:
        module = importlib.import_module(name)
        harness.isolate()
        harness.setup_host()
        result = module.run()
        (output / f'{name}.json').write_text(json.dumps(result, indent=2, ensure_ascii=False))
        return int(bool(result['counts']['fail'] or result['counts']['error']))
    except BaseException:
        traceback.print_exc()
        return 2


def summary(name, output):
    path = output / f'{name}.json'
    if not path.exists():
        return f'{name}: no result'
    result = json.loads(path.read_text())
    counts = ' '.join(f'{k} {v}' for k, v in result['counts'].items())
    statuses = {c['name']: c['status'] for c in result['cases']}
    lines = [f'{name}: {counts}']
    for group, g in result['coverage'].items():
        lines.append(f'  {group} {g["covered"]}/{g["total"]}')
        for item, entry in g['items'].items():
            if not entry['cases']:
                lines.append(f'    {"NONE":<5} {item:<18} {entry["text"]}')
            for case in entry['cases']:
                status = {'pass': 'ok', 'fail': 'FAIL', 'error': 'ERROR'}[statuses[case]]
                lines.append(f'    {status:<5} {item:<18} {entry["text"]} ({case})')
    if result['not_asserted']:
        lines.append('  not asserted')
        for item, text in result['not_asserted'].items():
            lines.append(f'    {item:<24} {text}')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suites', nargs='*', choices=SUITES, default=SUITES)
    parser.add_argument('--output', type=Path, help='new directory for results.json files')
    args = parser.parse_args()
    if args.output:
        args.output.mkdir(parents=True)
        output = args.output.resolve()
    else:
        output = Path(tempfile.mkdtemp(prefix='nftables-tests-'))
    print(f'Results: {output}', flush=True)
    children = {}
    for name in dict.fromkeys(args.suites):
        pid = os.fork()
        if pid == 0:
            os._exit(child(name, output))
        children[pid] = name
    status = 0
    while children:
        pid, code = os.wait()
        name = children.pop(pid)
        code = os.waitstatus_to_exitcode(code)
        status = max(status, code if code >= 0 else 2)
        print(summary(name, output), flush=True)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
