from pwn import *
import binascii
import subprocess
import re
import angr
import pickle
from pprint import pprint
import os

archive = 'amd64'

context(os='linux', arch=archive, log_level='info')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']


def get_i1_i2(file_o0):
    o0 = ELF(file_o0)
    result = subprocess.run(['readelf', '-S', file_o0],
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    result = re.search(
        r'.text\s+PROGBITS\s+(?P<addr>[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s*' + '\n'
        r'\s*(?P<length>[0-9a-fA-F]+)', result.stdout)

    code = o0.disasm(int(result.group('addr'), 16),
                     int(result.group('length'), 16))
    try:
        code = code[0:re.search(r'\(bad\)', code).span()[0]]
    except Exception as e:
        pass

    pattern1 = re.compile(r'^.*?mov.*?\[.*?\].*?$', flags=re.MULTILINE)  # 一般
    pattern2 = re.compile(r'^.*?mov.*?$', flags=re.MULTILINE)
    pattern3 = re.compile(r'^.*?r[8|9|10|11|12|13|14|15].*?$',
                          flags=re.MULTILINE)  # 比较稳
    pattern4 = re.compile(r'^.*?cmovl.*?$', flags=re.MULTILINE)  # 小项目不太行
    print("mov 内存指令: 所有指令", '\t',
          len(pattern1.findall(code)) / int(result.group('length'), 16))
    #  print("mov 内存指令: 所有mov指令", '\t',
    #        len(pattern1.findall(code)) / len(pattern2.findall(code)))
    print("r8~r15指令: 所有指令", '\t',
          len(pattern3.findall(code)) / int(result.group('length'), 16))
    print("cmovl指令个数", '\t', len(pattern4.findall(code)))
    return len(pattern1.findall(code)) / int(result.group('length'), 16), len(
        pattern3.findall(code)) / int(result.group('length'), 16)


def get_all(file_o0):
    o0 = ELF(file_o0)
    result = subprocess.run(['readelf', '-S', file_o0],
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    result = re.search(
        r'.text\s+PROGBITS\s+(?P<addr>[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s*' + '\n'
        r'\s*(?P<length>[0-9a-fA-F]+)', result.stdout)
    code_base = int(result.group('addr'), 16)
    code_length = int(result.group('length'), 16)
    code = o0.disasm(int(result.group('addr'), 16),
                     int(result.group('length'), 16))
    try:
        code = code[0:re.search(r'\(bad\)', code).span()[0]]
    except Exception as e:
        pass

    pattern1 = re.compile(r'^.*?mov.*?\[.*?\].*?$', flags=re.MULTILINE)  # 一般
    pattern2 = re.compile(r'^.*?mov.*?$', flags=re.MULTILINE)
    pattern3 = re.compile(r'^.*?r[8|9|10|11|12|13|14|15].*?$',
                          flags=re.MULTILINE)  # 比较稳
    pattern4 = re.compile(
        r'^.*?(?:cmovl|cmove|cmovz|cmovne|cmovnz|cmovs|cmovns|cmovg|cmovnle|cmovge|cmovnl|cmovl|cmovnge|cmovle|cmovng|cmova|cmovnbe|cmovae|cmovnb|cmovb|cmovnae|cmovbe|cmovna).*?$',
        flags=re.MULTILINE)  # 小项目不太行
    pattern5 = re.compile(
        r'^.*?\b(?:add|adc|inc|aaa|daa|sub|sbb|dec|nec|aas|das|mul|imul|aam|div|idiv|aad|cbw|cwd|cwde|cdq)\b.*?\[.*?\].*?$',
        flags=re.MULTILINE | re.IGNORECASE)  # removed
    pattern6 = re.compile(
        r'^.*?\b(?:push|pop)\b.*?r[8|9|10|11|12|13|14|15].*?$',
        flags=re.MULTILINE)

    pattern7 = re.compile(r'push\s+rbp\s*\n\s*.*?mov\s+rbp\s*,\s*rsp',
                          flags=re.MULTILINE)

    proj = angr.Project(file_o0, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFG()
    l = list(proj.kb.functions.items())
    s = list(map(lambda x: (hex(x[0]), x[1], x[1].alignment), l))
    cnt0 = 0
    cnt1 = 0
    print(hex(code_base), hex(code_base + code_length))
    if code_base < 0x400000:
        code_base += 0x400000
    for i in s:
        if (i[2] is False):
            if (code_base <= int(i[0], 16) <= code_base + code_length):
                cnt0 += 1
                print(i)
                if (i[0][-1] == '0'):
                    cnt1 += 1
    return len(pattern1.findall(code)) / int(result.group('length'), 16), len(
        pattern3.findall(code)) / int(result.group('length'),
                                      16), cnt1 / cnt0, len(
                                          pattern7.findall(code)) / cnt0, len(
                                              pattern4.findall(code)), file_o0


def save_data(file_list, file2save):
    dataset = []
    for file in file_list:
        if '_O0' in file:
            val = 0
        elif '_O1' in file:
            val = 1
        elif '_O2' in file:
            val = 2
        dataset.append([get_all(file), val])

    with open(file2save, 'wb') as f:
        pickle.dump(dataset, f)


def recursive_files(path):
    file_dir_list = os.listdir(path)
    file_list = []
    for f_or_d in file_dir_list:
        if os.path.isdir(os.path.join(path, f_or_d)):
            files = recursive_files(os.path.join(path, f_or_d))
            for item in files:
                file_list.append(os.path.join(path, f_or_d, item))
        else:
            file_list.append(os.path.join(path, f_or_d))
    return file_list


if __name__ == '__main__':
    #  file_list = recursive_files(
    #      '/home/v1me/proj/graduation_thesis/project/test/samples')
    #  save_data(file_list, os.path.join(os.getcwd(), 'pickle_data.dump'))

    path = '/home/v1me/proj/graduation_thesis/project/test/samples/sample_group_3'

    file_list = list(map(lambda x: os.path.join(path, x), os.listdir(path)))

    with open('/home/v1me/proj/graduation_thesis/log.txt', 'w') as f, open(
            os.path.join(
                '/home/v1me/proj/graduation_thesis/project/test/pickle',
                os.path.basename(path) + '.dump'), 'wb') as pick:
        data_set = []
        for file in file_list:
            if '_O0' in file:
                val = 0
            elif '_O1' in file:
                val = 1
            elif '_O2' in file:
                val = 2
            l = get_all(file)
            data_set.append([l, val])
            f.write('=========================\n')
            for i in l:
                f.write(str(i))
                f.write('\n')
            f.write('=========================')
            f.write('\n')

        pickle.dump(data_set, pick)
