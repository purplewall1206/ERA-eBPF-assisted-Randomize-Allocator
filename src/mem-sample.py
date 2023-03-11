import psutil
import time

FILE_NAME = 'memusage/ERA_test0.txt'
# FILE_NAME = 'memusage/ERA_kof_so.txt'
# FILE_NAME = 'memusage/vanilla.txt'
mem_list = list()

try:
    while True:
        time.sleep(1)
        d = dict(psutil.virtual_memory()._asdict())
        # print(d)
        mem_list.append(d)
except KeyboardInterrupt:
    print('end')
    with open(FILE_NAME, 'w') as f:
        for x in mem_list:
            line = str(x['used']) + ' ' + str(x['available']) + ' ' + str(x['free']) + ' ' + str(x['slab']) + '\n'
            f.write(line)

# used available free slab
