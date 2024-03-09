import angr
import claripy

# 바이너리 파일 경로와 인수 목록을 입력으로 받아서 Command Line Argument 생성
def create_argv(binary, args):
    argv = []
    argv.append(binary)
    if args:
        for l in args:
            argv.append(claripy.BVS('argv_' + hex(l), 8*l))
    return argv

# 중복된 요소를 제거한 새로운 리스트 반환
def strip_list(inlist):
    tmp = []
    tmp.append(inlist[0])
    for i in range(len(inlist)):
        if i == len(inlist) - 1:
            break
        this = inlist[i]
        this_next = inlist[i+1]
        if this != this_next:
            tmp.append(this_next)
        else:
            continue
    return tmp

# 특정 상태(state)와 히스토리 리스트(hist_list)를 기반으로 함수의 심볼과 주소를 추출하여 결과를 생성하는 기능
def deal_history(state, hist_list):
    filename = state.globals['filename']
    sm = angr.Project(filename, auto_load_libs=False)
    sm.analyses.CFG()
    import_dir = sm.loader.main_object.symbols_by_name
    import_filter = {}
    for k in import_dir:
        if (import_dir[k].is_local or import_dir[k].is_export) and import_dir[k].is_function:
            import_filter[import_dir[k].rebased_addr] = import_dir[k].name
            
    tmp_dir = {}
    for k in import_filter:
        func = sm.kb.functions.function(name=import_filter[k])
        tmp = func.block_addrs_set
        for x in tmp:
            tmp_dir[x] = import_filter[k] + "+" + hex(x-k)
            
    entry = sm.entry & 0xfff000
    func_plt = sm.loader.main_object.plt
    func_plt = {value:key + "~plt" for key, value in func_plt.items()}
    func_plt.update(tmp_dir)
    
    for k in func_plt:
        if func_plt[k] == 'main+0x0':
            main_addr = k
    
    flag = 0
    result = "[1]"
    for x in hist_list:
        if x & 0xfff000 != entry:
            hist_list.remove(x)
    
    hist_list = strip_list(hist_list)
        
    for h in hist_list:
        for key in func_plt:
            if h == key:
                if h == main_addr:
                    result += "\n[2]" + hex(h) + "{" + func_plt[key] + "}" + "-->"
                else:
                    result += hex(h) + "{" + func_plt[key] + "}" + "-->"
                flag = 1
                break
            
            else:
                flag = 0
        
        if flag == 0:
            result += hex(h) + "-->"
            
    return hist_list, result[:-3]    


# 두 개의 문자열의 최소 편집 거리(Minimum Edit Distance)와 유사도 비율(ratio) 계산
def min_distance(str1, str2):
    len_str1 = len(str1) + 1
    len_str2 = len(str2) + 1
    
    # Create Matrix
    matrix = [0 for n in range(len_str1 * len_str2)]
    
    # Init x-axis
    for i in range(len_str1):
        matrix[i] = i
    
    # Init y-axis
    for j in range(0, len(matrix), len_str1):
        if j % len_str1 == 0:
            matrix[j] = j // len_str1
        
    for i in range(1, len_str1):
        for j in range(1, len_str2):
            if str1[i-1] == str2[j-1]:
                cost = 0
            else:
                cost = 1
            matrix[j*len_str1+i] = min(matrix[(j-1)*len_str1+i]+1, 
                                       matrix[j*len_str1+(i-1)]+1,
                                       matrix[(j-1)*len_str1+(i-1)]+cost)
    min_dis = matrix[-1]
    ratio = (max(len_str1, len_str2) - min_dis) / max(len_str1, len_str2)
    
    return min_dis, ratio

# 문자열 간의 최소 편집 거리 계산을 이용하여 중복 경로를 탐지하는 기능을 수행            
def cmp_path(inpath, outpath, limit):
    if outpath:
        tmp = []
        for alist in outpath:
            dis, ratio = min_distance(alist, inpath)
            tmp.append(dis)
        min_dis = min(tmp)
        
        if min_dis <= limit:
            print("\033[42m[-] find a repeat path, drop it\033[0m")
            print("min_dis is", min_dis)
            return False
        else:
            outpath.append(inpath)
            return True
        
    else:
        outpath.append(inpath)
        return True
