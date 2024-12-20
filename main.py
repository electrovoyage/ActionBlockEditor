from tkinter.font import Font
from ttkbootstrap import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter.filedialog import askopenfilename, asksaveasfilename
import re
from tktooltip import ToolTip
from mccommands import mccommands

win = Window('ActionBlock Editor', themename='darkly', size=(480, 320))

NORMAL_FONT = Font(win, family='Consolas', size=16)
BOLD = Font(win, family='Consolas', size=16, weight='bold')
ITALIC = Font(win, family='Consolas', size=16, slant='italic')

actionframe = Frame(win)
actions: Text = Text(actionframe, font=NORMAL_FONT, tabs=50, height=win.winfo_screenheight())
actions.pack(fill=BOTH, expand=True)

command_syntax_hightlighting_options = {'foreground': '#FFAA00'}

syntax_regexes = {
    'string': r'"((?:[^"\\]|\\.)*?)"',
    'resource': r'[a-zA-Z_/]+[:/][a-zA-Z_/.]+',
    'entity_specifier': r'([@][sap])|([@][e]([\[][a-zA-Z0-9\=,\" .\{\}-]+[\]])?)',
    'tagged_object': r'[{][{}_\"a-zA-Z0-9: ,]+[}]',
    'object_properties': r'[\[][a-zA-Z0-9\=,\" .\{\}-]+[\]]',
    'number': r'[~^]?([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[Ee]([+-]?\d+))?',
    'mistake': r'//statement//'
}

def dark_title_bar(window: Window):
    '''
    Make window have a dark title bar.
    '''
    import ctypes as ct
    window.update()
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    set_window_attribute = ct.windll.dwmapi.DwmSetWindowAttribute
    get_parent = ct.windll.user32.GetParent
    hwnd = get_parent(window.winfo_id())
    rendering_policy = DWMWA_USE_IMMERSIVE_DARK_MODE
    value = 2
    value = ct.c_int(value)
    set_window_attribute(hwnd, rendering_policy, ct.byref(value), ct.sizeof(value))
    
dark_title_bar(win)

tags = ('command', 'number', 'string', 'semicolon', 'mistake', 'resource', 'entity_specifier', 'tagged_object', 'object_properties')
actions.tag_configure('command', **command_syntax_hightlighting_options)
actions.tag_configure('number', font=BOLD, foreground='#3489eb')
actions.tag_configure('string', font=ITALIC, foreground='#7feba6', tabstyle='wordprocessor')
actions.tag_configure('resource', foreground='#0bbd14', font=ITALIC)
actions.tag_configure('entity_specifier', foreground='#7986fc', font=ITALIC)
actions.tag_configure('semicolon', foreground='#b07cde')
actions.tag_configure('tagged_object', foreground='#e985ff')
actions.tag_configure('object_properties', foreground='#a579fc')
actions.tag_configure('mistake', underline=True, underlinefg='red')

FilePathVar = StringVar(win, '')

INDICATOR_ENABLED = '#FFFFFF'
INDICATOR_DISABLED = '#757575'

missing_semicolon_var = BooleanVar()
missing_semicolon_var.trace_add('write', lambda *args: missing_semicolon_indic.configure(foreground=INDICATOR_ENABLED if missing_semicolon_var.get() else INDICATOR_DISABLED))

def coords():
    row, column = list(map(int, actions.index(INSERT).split('.')))
    
    column += 1
    
    pos.configure(text=f'Line {row}, column {column}')
    
global lines_with_missing_semicols
lines_with_missing_semicols = []

def highlight():
    #actions = Text()
    
    global lines_with_missing_semicols
    lines_with_missing_semicols = []
    missing_semicolon_var.set(False)
    
    for tag in tags:
        actions.tag_remove(tag, '1.0', END)
    
    for ind, line in enumerate(actions.get('1.0', 'end-1c').split('\n')):
        line: str
        _line: str = line.strip()
        
        if _line == '':
            continue
        
        for command in mccommands:
            if _line.startswith(command):
                start = _line.find(command)
                actions.tag_add('command', f'{ind + 1}.{start}', f'{ind + 1}.{start + len(command)}')
                
        last_char_of_line = (f'{ind + 1}.{len(line) - 1}', f'{ind + 1}.{len(line)}')
                
        for tag, regex in syntax_regexes.items():
            matches = re.finditer(regex, _line)

            for match_ in matches:
                start = f'{ind + 1}.{match_.start()}'
                end = f'{ind + 1}.{match_.end()}'
                actions.tag_add(tag, start, end)
                
        if not _line.endswith(';'):
            actions.tag_add('mistake', *last_char_of_line)
            missing_semicolon_var.set(True)
            lines_with_missing_semicols.append(ind + 1)
        else:
            actions.tag_add('semicolon', *last_char_of_line)
            
        #if ACTIONSEP in _line:
        #    start = f'{ind + 1}.{_line.index(ACTIONSEP)}'
        #    end = f'{ind + 1}.{_line.index(ACTIONSEP) + len(ACTIONSEP)}'
        #    
        #    actions.tag_add('mistake', start, end)
            
    is_illegal_sep_present()
    win.after(100, highlight)

actions.bind('<KeyRelease>', lambda x: coords())
actions.bind('<ButtonRelease-1>', lambda x: coords())

menu = Menu(win)
win.configure(menu=menu)

filemenu = Menu(menu)
menu.add_cascade(menu=filemenu, label='File')

def openfile():
    f = askopenfilename(defaultextension='.mcab', filetypes=[('ActionBlock code', '.mcab')], parent=win)
    
    if f:
        openfrompath(f)
        
def saveasfile():
    f = asksaveasfilename(defaultextension='.mcab', filetypes=[('ActionBlock code', '.mcab')], parent=win)
    if f:
        savetopath(f)
        
def savetopath(f: str):
    FilePathVar.set(f)
    with open(f, 'w') as code:
        code.write(actions.get('0.0', END).strip('\n\r'))
        
    filemenu.entryconfigure(3, state=NORMAL)
        
def openfrompath(f: str):
    FilePathVar.set(f)
        
    with open(f, 'r') as code:
        contents = code.read() # just in case reading errors, read first, erase previous contents second
        actions.delete('0.0', END)
        actions.insert(END, contents)
        
    filemenu.entryconfigure(3, state=NORMAL)

# TODO: actually add the about menu
# requires the mod to be done to add logo
filemenu.add_command(label='About')
filemenu.add_separator()
filemenu.add_command(label='Open', command=openfile)
filemenu.add_command(label='Save', command=lambda: savetopath(FilePathVar.get()), state=DISABLED)
filemenu.add_command(label='Save as', command=saveasfile)
filemenu.add_separator()
filemenu.add_command(label='Quit', command=win.quit)

exportmenu = Menu(menu)
menu.add_cascade(menu=exportmenu, label='Export')

export_win = Toplevel('Export', resizable=(False, False), minsize=(300, 150))
dark_title_bar(export_win)
#export_win.withdraw()

export_win_open = BooleanVar(export_win, False)

export_status_text = Label(export_win, text='...')
export_status_text.pack(side=TOP, anchor=S, fill=BOTH, pady=10, padx=10)

export_code_frame = Labelframe(export_win, padding=5, text='Output')
export_code_frame.pack(side=TOP, fill=X, padx=10, pady=10)
export_code_output = Entry(export_code_frame)
export_code_output.pack(fill=X)

def hide_export_win():
    export_win.grab_release()
    export_win_open.set(False)
    export_win.withdraw()
    
export_win.wm_protocol('WM_DELETE_WINDOW', hide_export_win)

STATUSFLAGS_SEMICOLON, STATUSFLAGS_ACTIONSEPARATOR = [2 ** i for i in range(2)]
ACTIONSEP = '//statement//'

def _is_illegal_sep_present() -> bool:
    return ACTIONSEP in actions.get('0.0', END)

def is_illegal_sep_present() -> bool:
    b = _is_illegal_sep_present()
    
    separator_indic.configure(foreground=INDICATOR_ENABLED if b else INDICATOR_DISABLED)
    return b

def make_code_status_flags() -> int:
    return (STATUSFLAGS_SEMICOLON if missing_semicolon_var.get() else 0) \
    | (STATUSFLAGS_ACTIONSEPARATOR if is_illegal_sep_present() else 0)

def make_code() -> str:
    text = actions.get('0.0', END)
    s = ''
    for _line in text.splitlines():
        line = _line.strip()
        s += line[:-1] + ACTIONSEP
        
    return s

def show_export_win():
    if export_win_open.get():
        export_win.focus()
        return
    
    export_win_open.set(True)
    export_win.deiconify()
    export_win.grab_set()
    
    status = make_code_status_flags()
    #print(status & STATUSFLAGS_SEMICOLON)
    
    status_str = ''
    export_code_output.delete(0, END)
    export_code_output.configure(state=DISABLED)
    if status & STATUSFLAGS_SEMICOLON:
        status_str += 'Missing semicolons:'
        for line in lines_with_missing_semicols:
            status_str += f'\n    - Line {line}'
            
        status_str += '\n'
            
    if status & STATUSFLAGS_ACTIONSEPARATOR:
        status_str += f'Found disallowed separator "{ACTIONSEP}" in code!'
            
    if status == 0:
        status_str = 'All good!'
        export_code_output.configure(state=NORMAL)
        export_code_output.insert(END, make_code())
        
    export_status_text.configure(text=status_str)

exportmenu.add_command(label='For ActionBlock...', command=show_export_win)

bottompanel = Frame(padding=5)
bottompanel.pack(side=BOTTOM, fill=X, expand=True, anchor=N)
actionframe.pack(side=TOP, fill=BOTH, expand=True)
status_imgs = Frame(bottompanel)
status_imgs.pack(side=RIGHT, anchor=E, fill=Y)

missing_semicolon_indic = Label(status_imgs, text=';', font=BOLD, foreground=INDICATOR_DISABLED, justify=CENTER)
missing_semicolon_indic.pack(side=RIGHT, anchor=E, ipadx=20, ipady=5)

separator_indic = Label(status_imgs, text='/', font=BOLD, foreground=INDICATOR_DISABLED, justify=CENTER)
separator_indic.pack(side=RIGHT, anchor=E, ipadx=20, ipady=5)

ToolTip(missing_semicolon_indic, lambda: 'Missing semicolons on following lines:\n' + '\n'.join([f' - Line {i}' for i in lines_with_missing_semicols]) if missing_semicolon_var.get() else 'No missing semicolons', parent_kwargs={'background': '#000000', 'padx': 1, 'pady': 1}, aspect=1000, background='#222222', foreground='#ffffff')
ToolTip(separator_indic, lambda: f'Found disallowed separator "{ACTIONSEP}"' if is_illegal_sep_present() else 'No disallowed separators found', parent_kwargs={'background': '#000000', 'padx': 1, 'pady': 1}, aspect=1000, background='#222222', foreground='#ffffff')

pos = Label(bottompanel, text='Line 1, column 1')
pos.pack(side=LEFT)

win.after(100, highlight)
win.mainloop()