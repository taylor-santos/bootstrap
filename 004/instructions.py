from copy import deepcopy

import json

with open('x86.json') as f:
    data = json.load(f)

encodings = {}
all_fields = {}
all_encs = {}
all_bitdiffs = {}
all_isas = {}
all_extensions = {}

deprecated_isas = [
    'KNCE',
    'KNCJKBR',
    'KNCSTREAM',
    'KNCV',
    'KNC_MISC',
    'KNC_PF_HINT',
]

for record in data['records']:
    if record['rectype'] != 'ENCODING': continue
    record.pop('rectype')
    if 'deprecated' in record['metadata']: continue
    if record['metadata']['isa'] in deprecated_isas: continue

    for ext in record['extensions']:
        all_extensions.setdefault(ext, 0)
        all_extensions[ext] += 1

    fields = {}
    for field in record['diagram']['fields']:
        assert 'name' in field and 'value' in field and len(field) == 2
        fields[field['name']] = field['value']
        all_fields.setdefault(field['name'], {}).setdefault(field['value'], 0)
        all_fields[field['name']][field['value']] += 1
    assert len(record['diagram']) == 1
    if 'MODE' in fields and fields.pop('MODE') == 'NO64':
        continue
    record['diagram'] = fields

    templates = record.pop('templates')
    assert all('bitdiffs' in temp and temp['bitdiffs'] is not None and 'MODE' in temp['bitdiffs']['fields'] for temp in templates) or \
           all('bitdiffs' not in temp or temp['bitdiffs'] is None or 'MODE' not in temp['bitdiffs']['fields'] for temp in templates)
    for temp in templates:
        if 'bitdiffs' in temp:
            if temp['bitdiffs'] is None:
                temp.pop('bitdiffs')
            else:
                fields = {}
                for field in temp['bitdiffs']['fields']:
                    fields[field['name']] = field['value']
                    all_bitdiffs.setdefault(field['name'], {}).setdefault(field['value'], 0)
                    all_bitdiffs[field['name']][field['value']] += 1
                assert len(temp['bitdiffs']) == 1
                temp['bitdiffs'] = fields

        temp['record'] = deepcopy(record)
        # temp['record']['templates'] = templates
        mnem = temp['syntax']['mnem']

        # Special case for INT1 and INT3, because the dataset doesn't represent these as imm operands
        if mnem in ['INT1', 'INT3']:
            temp['syntax']['ast'].append({
                'type': 'IMM',
                'datatype': 'U8',
                'value': mnem[3],
            })
            mnem = temp['syntax']['mnem'] = 'INT'

        encodings.setdefault(mnem, []).append(temp)
        all_isas.setdefault(record['metadata']['isa'], set()).add(mnem)

def dict_sort(d):
    for k,v in sorted(d.items()):
        del d[k]
        d[k] = v

dict_sort(all_isas)

md = set()
tuples = set()

encodings = dict(sorted(encodings.items()))


def out(*args, **kwargs):
    print(*args, **kwargs)
    pass


datatypes = {}
sizes = {}

for mnem, encs in encodings.items():
    out(f"  INSTRUCTION({mnem.lower()},")
    for encoding in encs:
        out(f"    ENCODING(")
        out('      .opcode    = 0x', end='')
        if 'MAP' in encoding['record']['diagram'] and 'ENC' not in encoding['record']['diagram']:
            map = encoding['record']['diagram'].pop('MAP')
            assert map[:2] == '0f'
            out(map.upper(), end='')
            map = None
        op = encoding['record']['diagram'].pop('OP')
        assert(op[:2] == '0x')
        out(f"{op[2:].upper()},")
        if 'metadata' in encoding:
            lock_types = [
                f"LOCK_{type.upper()}"
                for type in ['lock', 'xacquire', 'xrelease']
                if encoding['metadata'].pop(type, False)
            ]
            if len(lock_types) > 0:
                out(f"      .lock      = ({'|'.join(lock_types)}),")

            rep_types = [
                f"REP_{type.upper()}"
                for type in ['rep', 'repz', 'repnz']
                if encoding['metadata'].pop(type, False)
            ]
            if len(rep_types) > 0:
                out(f"      .rep       = ({'|'.join(rep_types)}),")

            if encoding['metadata'].pop('bound', False):
                # unknown FIXME
                pass

            if encoding['metadata'].pop('egran', False):
                # unknown FIXME
                pass

            if encoding['metadata'].pop('bhint', False):
                # branch prediction hint
                pass

            if encoding['metadata'].pop('hle', False):
                # hardware lock elision
                pass

            tupletype = encoding['metadata'].pop('tuple', False)
            if tupletype:
                tuples.add(tupletype)
                out(f"      .tuple     = TUPLE_{tupletype},")
        assert len(encoding.pop('metadata', {})) == 0

        for prefix in ['P66', 'PF2', 'PF3']:
            p = encoding['record']['diagram'].pop(prefix, False)
            if p == '1':
                out(f"      .{prefix}       = PREFIX_REQUIRED,")
            elif p == '0':
                out(f"      .{prefix}       = PREFIX_DISALLOWED,")

        if 'ENC' in encoding['record']['diagram']:
            enc = encoding['record']['diagram'].pop('ENC')
            out('      .vex = {')
            if enc == 'XOP':
                out(f"        .type    = XOP_8F,")
                if 'W' in encoding['record']['diagram']:
                    w = encoding['record']['diagram'].pop('W')
                    out(f"        .W_E     = {w},")
                elif 'bitdiffs' in encoding and  'W' in encoding['bitdiffs']:
                    assert False
                    w = encoding['bitdiffs'].pop('W')
                    out(f"        .W_E     = W{w},")
                else:
                    out('        .W_E     = WIG,')

                if 'VL' in encoding['record']['diagram']:
                    l = encoding['record']['diagram'].pop('VL')
                    out(f"        .L       = L{l},")
                else:
                    assert 'bitdiffs' in encoding and 'VL' in encoding['bitdiffs']
                    l = encoding['bitdiffs'].pop('VL')
                    out(f"        .L       = {l},")

                map = encoding['record']['diagram'].pop('MAP')
                if map == 'xop8':
                    out('        .mmmmm   = 0b01000,')
                elif map == 'xop9':
                    out('        .mmmmm   = 0b01001,')
                elif map == 'xopa':
                    out('        .mmmmm   = 0b01010,')
                else:
                    assert map == 'xopb'
                    out('        .mmmmm   = 0b01011,')
            elif enc == 'VEX':
                out(f"        .type    = VEX_C4,")
                if 'W' in encoding['record']['diagram']:
                    w = encoding['record']['diagram'].pop('W')
                    out(f"        .W_E     = {w},")
                elif 'bitdiffs' in encoding and  'W' in encoding['bitdiffs']:
                    w = encoding['bitdiffs'].pop('W')
                    out(f"        .W_E     = W{w},")
                else:
                    out('        .W_E     = WIG,')

                if 'VL' in encoding['record']['diagram']:
                    l = encoding['record']['diagram'].pop('VL')
                    out(f"        .L       = L{l},")
                elif 'bitdiffs' in encoding and 'VL' in encoding['bitdiffs']:
                    l = encoding['bitdiffs'].pop('VL')
                    out(f"        .L       = {l},")
                else:
                    out('        .L       = LIG,')

                map = encoding['record']['diagram'].pop('MAP')
                if map == '0f':
                    out('        .mmmmm   = 0b00001,')
                elif map == '0f38':
                    out('        .mmmmm   = 0b00010,')
                else:
                    assert map == '0f3a'
                    out('        .mmmmm   = 0b00011,')
            else:
                assert enc == 'EVEX'
                out(f"        .type    = EVEX_62,")
                ...
            out('      },')
        # assert 'MAP' not in encoding['record']['diagram']
        # assert 'BP' not in encoding['record']['diagram']
        # assert 'VL' not in encoding['record']['diagram'] # FIXME
        # assert 'E' not in encoding['record']['diagram']

        if 'REG' in encoding['record']['diagram'] and encoding['record']['diagram']['REG'] == 'NNN':
            ...

        ops = [op for op in encoding['syntax'].pop('ast') if 'suppressed' not in op]

        out(f"      .op_count  = {len(ops)},")
        out('      .ops = {')
        for op in ops:
            type = op.pop('type')
            def print_op(operand):
                out(f"        OP_{operand},")
            if type == 'REG':
                if 'value' in op:
                    value = op.pop('value')
                    if value == 'AL':
                        print_op('R_A(8)')
                    elif value == 'AX':
                        print_op('R_A(16)')
                    elif value == 'EAX':
                        print_op('R_A(32)')
                    elif value == 'CL':
                        print_op('R_C(8)')
                    elif value == 'ECX':
                        print_op('R_C(32)')
                    elif value == 'DX':
                        print_op('R_D(16)')
                    elif value in ['FS', 'GS']:
                        print_op(f"R_{value}")
                    else:
                        assert value == 'ST0'
                        assert op['datatype'] == 'F80'
                        print_op('R_ST0')
                        ...
                else:
                    assert 'symbol' in op
                    symbol = op.pop('symbol')
                    if symbol == 'AXv':
                        print_op('R_AXV')
                    elif symbol[:3] == 'GPR':
                        assert symbol[3:] in ['8', '16', '32', '64', 'a', 'v', 'y', 'z']
                        print_op(f"R_{symbol.upper()}")
                        assert 'datatype' not in op or op['datatype'] in ['U8', 'U16', 'U32', 'S32', 'F32', 'U64', 'S64', 'SX']
                    elif symbol == 'XMMREG':
                        print_op('R_XMM')
                        assert op['datatype'] in ['U8', 'U16', 'U32', 'F32', 'S32', 'F64', 'U64', 'S64', 'U128']
                    elif symbol == 'YMMREG':
                        print_op('R_YMM')
                        assert op['datatype'] in ['U256']
                    elif symbol == 'MMXREG':
                        print_op('R_MMX')
                        assert op['datatype'] in ['U8', 'S8', 'U16', 'S16', 'U32', 'S32', 'F32', 'U64', 'S64']
                    elif symbol == 'BNDREG':
                        assert 'datatype' not in op
                        print_op('R_BND')
                    elif symbol == 'FPREG':
                        assert op['datatype'] == 'F80'
                        print_op('???')
                    elif symbol == 'MASKREG':
                        assert 'datatype' not in op or op['datatype'] in ['U8', 'U16', 'U32', 'U64']
                        print_op('???')
                    elif symbol == 'SEGREG':
                        assert 'datatype' not in op
                        print_op('???')
                    elif symbol == 'CREG':
                        assert 'datatype' not in op
                        print_op('???')
                    else:
                        assert symbol == 'DREG'
                        assert 'datatype' not in op
                        print_op('???')
            elif type == 'MEM':
                size = op.pop('size')
                datatypes.setdefault(size, set()).add(op.get('datatype'))
                sizes.setdefault(op.get('datatype'), set()).add(size)

                if size == 8:
                    print_op('MEM(8)')
                elif size == 16:
                    print_op('MEM(16)')
                elif size == 32:
                    print_op('MEM(32)')
                elif size == 64:
                    print_op('MEM(64)')
                elif size == 80:
                    print_op('MEM(80)')
                elif size == 112:
                    print_op('MEM(112)')
                elif size == 128:
                    print_op('MEM(128)')
                elif size == 224:
                    print_op('MEM(224)')
                elif size == 256:
                    print_op('MEM(256)')
                elif size == 512:
                    print_op('MEM(512)')
                elif size == 752:
                    print_op('MEM(752)')
                elif size == 864:
                    print_op('MEM(864)')
                elif size == 4096:
                    print_op('MEM(4096)')
                elif size == 4608:
                    print_op('MEM(4608)')
                elif size == 'SZ_V':
                    print_op('MEM_V')
                elif size == 'SZ_Y':
                    print_op('MEM_Y')
                elif size == 'SZ_PPR':
                    print_op('MEM_PPR')
                else:
                    assert size == 'SZ_DPR'
                    print_op('MEM_DPR')
            elif type == 'IMM':
                if 'value' in op:
                    value = op.pop('value')
                    print_op(f"IMM_{value}")
                else:
                    size = op.pop('size')
                    print_op(f"IMM({size})")
            elif type == 'VREG':
                if 'value' in op:
                    value = op.pop('value')
                    print_op('???')
                else:
                    assert 'symbol' in op
                    symbol = op.pop('symbol')
                    if symbol == 'XMMREG':
                        print_op('???')
                    elif symbol == 'YMMREG':
                        print_op('???')
                    elif symbol == 'ZMMREG':
                        print_op('???')
                    else:
                        assert symbol == 'MMXREG'
                        print_op('???')
            elif type == 'PTR':
                print_op('???')
            elif type == 'AGEN':
                print_op('???')
            elif type == 'REL':
                print_op('???')
            elif type == 'CC':
                print_op('???')
            elif type == 'SHIFT':
                print_op('???')
            elif type == 'MOFFS':
                print_op('???')
            elif type == 'ORDER':
                print_op('???')
            elif type == 'ROTATE':
                print_op('???')
            elif type == 'RNDC':
                print_op('???')
            elif type == 'PREG':
                print_op('???')
            elif type == 'BCST':
                print_op('???')
            elif type == 'RC':
                print_op('???')
            elif type == 'SAE':
                print_op('???')
            elif type == 'FEXCPC':
                print_op('???')
            elif type == 'FPCT':
                print_op('???')
            elif type == 'SIGNC':
                print_op('???')
            elif type == 'CTL':
                print_op('???')
            else:
                assert type == 'MIB'
                print_op('???')
        out('      },')
        out('    ),')
    out("  ),")

exit()
