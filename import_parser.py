# -*- coding: utf-8 -*-
"""
教务 Excel 导入解析器
支持：班级课程计划表（班级块）、教师课程计划表（教师块）、班级课程表（每班一 sheet）、教师课程表（每师一 sheet）
返回纯 Python 结构，供导入预览与确认使用。
"""
import re
from collections import OrderedDict


def _is_noise(s):
    """过滤标题/页码等噪声行"""
    if not s:
        return True
    if '页(共' in s:
        return True
    if s.startswith('2026') or s.startswith('2025') or s.startswith('2024'):
        return True
    if s in ('课程计划表', '教师课程计划表', '班级课程计划表', '合计课时数：'):
        return True
    return False


def _clean_hours(v):
    s = str(v).strip() if v is not None else ''
    if s.isdigit():
        return int(s)
    m = re.search(r'\d+(\.\d+)?', s)
    return float(m.group()) if m else 0


def parse_class_plan(filepath):
    """班级课程计划表 → (classes, tasks)
    结构：班级块标题(A列) → 表头行 → 数据行(课程/教师/节数/场地) → 合计行"""
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True)
    ws = wb[wb.sheetnames[0]]
    classes, tasks = [], []
    cur = None
    for row in ws.iter_rows(values_only=True):
        a = str(row[0]).strip() if row[0] is not None else ''
        b = str(row[1]).strip() if len(row) > 1 and row[1] is not None else ''
        c = str(row[2]).strip() if len(row) > 2 and row[2] is not None else ''
        d = str(row[3]).strip() if len(row) > 3 and row[3] is not None else ''
        f = str(row[5]).strip() if len(row) > 5 and row[5] is not None else ''
        if not a and not b and not c:
            continue
        if b == '课程名称' or (b == '班级名称' and c == '课程名称'):
            continue  # 表头行
        if a and not b:
            if _is_noise(a):
                continue
            cur = a
            if a not in classes:
                classes.append(a)
            continue
        if b and c and cur:
            tasks.append({'class': cur, 'course': b, 'teacher': c,
                          'hours': _clean_hours(d), 'venue': f})
    return classes, tasks


def parse_teacher_plan(filepath):
    """教师课程计划表 → (teachers, tasks)
    结构：教师块标题(A列) → 表头行 → 数据行(班级/课程/节数/场地)"""
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True)
    ws = wb[wb.sheetnames[0]]
    teachers, tasks = [], []
    cur = None
    for row in ws.iter_rows(values_only=True):
        a = str(row[0]).strip() if row[0] is not None else ''
        b = str(row[1]).strip() if len(row) > 1 and row[1] is not None else ''
        c = str(row[2]).strip() if len(row) > 2 and row[2] is not None else ''
        d = str(row[3]).strip() if len(row) > 3 and row[3] is not None else ''
        f = str(row[5]).strip() if len(row) > 5 and row[5] is not None else ''
        if not a and not b and not c:
            continue
        if b == '课程名称' or (b == '班级名称' and c == '课程名称'):
            continue
        if a and not b:
            if _is_noise(a):
                continue
            cur = a
            if a not in teachers:
                teachers.append(a)
            continue
        if b and c and cur:
            tasks.append({'teacher': cur, 'class': b, 'course': c,
                          'hours': _clean_hours(d), 'venue': f})
    return teachers, tasks


def _parse_schedule_sheet(ws):
    """解析一个课表 sheet（表头 R3：周一~五；R4-R10：节次1-7）
    格子格式：'课程名\\n教师名'（2行）或 '课程名\\n教师名\\n机房N'（3行，机房课）
    返回 cells: [{weekday, period, course, teacher, venue}]"""
    cells = []
    for ri in range(4, 11):
        if ri > ws.max_row:
            break
        first = ws.cell(row=ri, column=1).value
        if first is None:
            continue
        first_s = str(first).strip()
        if not first_s.startswith('上午') and not first_s.startswith('下午'):
            continue  # 非节次行（如页码行）
        period = ri - 3
        for wd in range(1, 6):  # 列 B-F = 星期一~五
            v = ws.cell(row=ri, column=wd + 1).value
            if v is None:
                continue
            txt = str(v).strip()
            if not txt:
                continue
            parts = [p.strip() for p in re.split(r'[\n\r]+', txt) if p.strip()]
            course = parts[0]
            venue = ''
            if len(parts) >= 3:
                # 3行：课程 / 教师 / 场地(机房N)
                teacher = parts[1]
                if parts[2] and ('机房' in parts[2] or '实训' in parts[2]):
                    venue = parts[2]
            else:
                teacher = parts[-1] if len(parts) > 1 else ''
                if teacher and ('机房' in teacher or '实训' in teacher
                                or re.match(r'^[一二三四五六七八九十]+\d*$', teacher)):
                    venue = teacher
                    teacher = ''
            cells.append({'weekday': wd, 'period': period,
                          'course': course, 'teacher': teacher, 'venue': venue})
    return cells


def parse_class_schedule(filepath):
    """班级课程表 → {班级名: {'room': '笃101', 'cells': [cells]}}
    班级本班教室从标题行提取（'25供电班课程表  ( 教室:笃101)'）"""
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True)
    result = OrderedDict()
    for sn in wb.sheetnames:
        if sn == 'Sheet1':
            continue
        ws = wb[sn]
        room = ''
        r2 = str(ws.cell(row=2, column=1).value or '')
        m = re.search(r'教室[：:]\s*([^\s）)]+)', r2)
        if m:
            room = m.group(1).strip()
        cells = _parse_schedule_sheet(ws)
        if cells or room:
            result[sn] = {'room': room, 'cells': cells}
    return result


def parse_teacher_schedule(filepath):
    """教师课程表 → {教师名: [cells]}（sheet 名 = 教师名；核对用）"""
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True)
    result = OrderedDict()
    for sn in wb.sheetnames:
        if sn == 'Sheet1':
            continue
        cells = _parse_schedule_sheet(wb[sn])
        if cells:
            result[sn] = cells
    return result
