import struct
import time


_CHAR_MAP = {}

for i, c in enumerate('abcdefghijklmnopqrstuvwxyz'):
    _CHAR_MAP[c] = (0x04 + i, 0x00)

for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    _CHAR_MAP[c] = (0x04 + i, 0x02)

for i, c in enumerate('123456789'):
    _CHAR_MAP[c] = (0x1e + i, 0x00)
_CHAR_MAP['0'] = (0x27, 0x00)

_SHIFT_DIGITS = {
    '!': 0x1e, '@': 0x1f, '#': 0x20, '$': 0x21, '%': 0x22,
    '^': 0x23, '&': 0x24, '*': 0x25, '(': 0x26, ')': 0x27,
}
for c, kc in _SHIFT_DIGITS.items():
    _CHAR_MAP[c] = (kc, 0x02)

_CHAR_MAP.update({
    ' ':  (0x2c, 0x00),  
    '\n': (0x28, 0x00),  
    '\t': (0x2b, 0x00),  
    '-':  (0x2d, 0x00),
    '=':  (0x2e, 0x00),
    '[':  (0x2f, 0x00),
    ']':  (0x30, 0x00),
    '\\': (0x31, 0x00),
    ';':  (0x33, 0x00),
    "'":  (0x34, 0x00),
    '`':  (0x35, 0x00),
    ',':  (0x36, 0x00),
    '.':  (0x37, 0x00),
    '/':  (0x38, 0x00),
})

_CHAR_MAP.update({
    '_': (0x2d, 0x02),
    '+': (0x2e, 0x02),
    '{': (0x2f, 0x02),
    '}': (0x30, 0x02),
    '|': (0x31, 0x02),
    ':': (0x33, 0x02),
    '"': (0x34, 0x02),
    '~': (0x35, 0x02),
    '<': (0x36, 0x02),
    '>': (0x37, 0x02),
    '?': (0x38, 0x02),
})


def char_to_hid(char):
    return _CHAR_MAP[char]



_SPECIAL_KEYS = {
    'enter':      0x28,
    'escape':     0x29,
    'backspace':  0x2a,
    'tab':        0x2b,
    'space':      0x2c,
    'capslock':   0x39,
    'f1': 0x3a, 'f2': 0x3b, 'f3': 0x3c, 'f4': 0x3d,
    'f5': 0x3e, 'f6': 0x3f, 'f7': 0x40, 'f8': 0x41,
    'f9': 0x42, 'f10': 0x43, 'f11': 0x44, 'f12': 0x45,
    'printscreen': 0x46,
    'insert':     0x49,
    'home':       0x4a,
    'pageup':     0x4b,
    'delete':     0x4c,
    'end':        0x4d,
    'pagedown':   0x4e,
    'right':      0x4f,
    'left':       0x50,
    'down':       0x51,
    'up':         0x52,
}

_MODIFIERS = {
    'ctrl_l':  0x01, 'shift_l': 0x02, 'alt_l': 0x04, 'win': 0x08,
    'ctrl_r':  0x10, 'shift_r': 0x20, 'alt_r': 0x40,
}


def send_key(keycode, modifier=0, hid_path='/dev/hidg0'):
    with open(hid_path, 'wb') as hid:
        hid.write(struct.pack('8B', modifier, 0, keycode, 0, 0, 0, 0, 0))
        hid.write(struct.pack('8B', 0, 0, 0, 0, 0, 0, 0, 0))


def send_string(text, delay=0.05, hid_path='/dev/hidg0'):
    for char in text:
        try:
            keycode, modifier = char_to_hid(char)
        except KeyError:
            print(f"[send_string] unknown character, skip: {char!r}")
            continue
        send_key(keycode, modifier, hid_path)
        time.sleep(delay)


def send_special_key(key, modifiers=None, hid_path='/dev/hidg0'):
    """
    Example:
        send_special_key('enter')
        send_special_key('x', modifiers=['win'])           # Win+X
        send_special_key('r', modifiers=['win'])           # Win+R
        send_special_key('escape', modifiers=['shift_l'])
    """
    modifiers = modifiers or []
    mod_byte = 0
    for m in modifiers:
        if m not in _MODIFIERS:
            raise KeyError(f"Unknown modifier: {m!r}")
        mod_byte |= _MODIFIERS[m]

    if key in _SPECIAL_KEYS:
        keycode = _SPECIAL_KEYS[key]
    elif len(key) == 1 and key.lower() in _CHAR_MAP:
        keycode, _ = char_to_hid(key.lower())
    else:
        raise KeyError(f"Unknown button: {key!r}")

    send_key(keycode, mod_byte, hid_path)

def open_admin_powershell(hid_path='/dev/hidg0', 
                           wait_menu=0.8, wait_uac=1.5):
    send_special_key('r', modifiers=['win'])
    time.sleep(wait_menu)

    send_string("powershell", delay=0.05)
 
    send_special_key('enter', modifiers=['ctrl_l', 'shift_l'], hid_path=hid_path)
    time.sleep(wait_uac)

    send_special_key('left', hid_path=hid_path)
    time.sleep(1)

    send_special_key('enter', hid_path=hid_path)
    time.sleep(1)

    send_special_key('tab', modifiers=['alt_l'])
    time.sleep(1)



